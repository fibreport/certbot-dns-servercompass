"""DNS Authenticator for servercompass.com."""
import logging
from typing import Any
from typing import Callable
from typing import Literal
from typing import Optional
from typing import Tuple
from typing import Union

import requests
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration
from requests.adapters import HTTPAdapter
from requests.utils import requote_uri
from urllib3.util import Retry

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    description = "Obtain certificates using a DNS TXT record (if you are using servercompass.com for DNS)."
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None], default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="servercompass.com credentials INI file.")

    def more_info(self) -> str:
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using the servercompass.com API."

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        if not credentials.conf("api-key"):
            raise errors.PluginError("{}: dns_servercompass_api_key is required.".format(credentials.confobj.filename))

        if credentials.conf("team-uuid") and credentials.conf("project-uuid"):
            raise errors.PluginError(
                "{}: dns_servercompass_team_uuid and dns_servercompass_project_uuid can't be set at the same time.".format(credentials.confobj.filename)
            )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "servercompass.com credentials INI file",
            None,
            self._validate_credentials,
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_api_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_api_client().del_txt_record(domain, validation_name, validation)

    def _get_api_client(self) -> "_DNSAPIClient":
        return _DNSAPIClient(
            api_key=self.credentials.conf("api-key"),
            api_endpoint=self.credentials.conf("api-endpoint"),
            team_uuid=self.credentials.conf("team-uuid"),
            project_uuid=self.credentials.conf("project-uuid"),
        )


class _DNSAPIClient:
    api_default_endpoint: str = "https://api.servercompass.com"
    api_endpoint: str = None
    api_key: str = None

    team_uuid: str = None
    project_uuid: str = None

    def __init__(
        self,
        api_key: str,
        api_endpoint: str | None = None,
        team_uuid: Optional[str] = None,
        project_uuid: Optional[str] = None,
    ) -> None:
        self.api_key = api_key
        self.api_endpoint = api_endpoint or self.api_default_endpoint

        self.team_uuid = team_uuid
        self.project_uuid = project_uuid

    def add_txt_record(self, domain: str, record_name: str, record_content: str, record_ttl) -> None:
        # get project and zone UUID
        project_uuid, zone_uuid = self._find_zone(domain)

        # create new TXT record
        self._api_request(
            url=f"/v1/projects/{project_uuid}/services/dns/zones/{zone_uuid}/records/",
            method="POST",
            data_json={
                "type": "TXT",
                "name": record_name,
                "ttl": record_ttl,
                "content": record_content,
            },
        )

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        # get project and zone UUID
        project_uuid, zone_uuid = self._find_zone(domain)

        # get record UUID
        record_uuid = self._find_zone_record(project_uuid, zone_uuid, record_name, record_content)

        # delete record
        self._api_request(
            url=f"/v1/projects/{project_uuid}/services/dns/zones/{zone_uuid}/records/{record_uuid}/",
            method="DELETE",
        )

    def _find_zone(self, domain: str) -> Tuple[str, str]:
        # remove any subdomain prefix
        domain = ".".join(domain.split(".")[-2:])

        # project is pre-filled
        if self.project_uuid and not self.team_uuid:
            # search for the DNS zone
            response = self._api_request(
                url=f"/v1/projects/{self.project_uuid}/services/dns/zones/",
                method="GET",
                query_parameters={"name": domain},
            )

            if response["count"] == 1:
                return self.project_uuid, response["results"][0]["uuid"]

        # if team is pre-filled
        elif self.team_uuid and not self.project_uuid:
            # iterate through each project
            for project in self._api_request(url=f"/v1/teams/{self.team_uuid}/projects/", method="GET"):
                # search for the DNS zone
                response = self._api_request(
                    url=f"/v1/projects/{project['uuid']}/services/dns/zones/",
                    method="GET",
                    query_parameters={"name": domain},
                )

                if response["count"] == 1:
                    return project["uuid"], response["results"][0]["uuid"]

        # fallback if no team or project UUIDs are pre-filled
        else:
            # iterate through each team
            for team in self._api_request(url="/v1/teams/", method="GET"):
                # iterate through each project
                for project in self._api_request(url=f"/v1/teams/{team['uuid']}/projects/", method="GET"):
                    # search for the DNS zone
                    response = self._api_request(
                        url=f"/v1/projects/{project['uuid']}/services/dns/zones/",
                        method="GET",
                        query_parameters={"name": domain},
                    )

                    if response["count"] == 1:
                        return project["uuid"], response["results"][0]["uuid"]

        raise errors.PluginError("Unable to find DNS zone. Please verify that the DNS zone exists or check your API key permissions.")

    def _find_zone_record(self, project_uuid: str, zone_uuid: str, record_name: str, record_content) -> str:
        zone_records = self._api_request(
            url=f"/v1/projects/{project_uuid}/services/dns/zones/{zone_uuid}/records/",
            method="GET",
            query_parameters={"type": "TXT", "name": record_name},
        )

        for zone_record in zone_records:
            if zone_record["content"] == record_content:
                return zone_record["uuid"]

        raise errors.PluginError("Unable to find TXT record in DNS zone. Please verify that the TXT record exists or check your API key permissions.")

    def _api_request(
        self,
        url: str,
        method: Literal["GET", "POST", "PATCH", "PUT", "DELETE"],
        query_parameters: Optional[Union[dict, list, tuple, bytes]] = None,
        data_json: Optional[dict] = None,
        timeout: Union[float, tuple[float, float], tuple[float, None]] = 120,
        max_retries: int = 5,
        retry_backoff_factor: int = 1,
    ) -> dict:
        if not hasattr(requests, method.lower()):
            raise Exception(f"Invalid request method: {method}")

        # headers
        headers = {
            "User-Agent": "Certbot DNS Plugin",
            "X-Auth-Token": self.api_key,
        }

        # append API endpoint
        url = f"{self.api_endpoint}{url}"

        # re-quote given uri
        url = requote_uri(url)

        # creat a new request session
        request_session = requests.session()

        # ignore env settings
        request_session.trust_env = False

        # configure retries
        request_retries = Retry(
            total=max_retries,
            backoff_factor=retry_backoff_factor,
            status_forcelist=[
                423,  # Locked
                429,  # To Many Requests
                500,  # Internal Server Error
                502,  # Bad Gateway
                503,  # Service Unavailable
                504,  # Gateway Timeout
                507,  # Insufficient Storage
            ],
            allowed_methods=["GET", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"],
        )

        # disallow http endpoints
        if url[0:7] == "http://":  # noqa
            raise Exception("Insecure API endpoint")

        # mount http(s) adapter
        request_session.mount("https://", HTTPAdapter(max_retries=request_retries))

        # send the request
        request = getattr(request_session, method.lower())(
            url=url,
            params=query_parameters,
            json=data_json,
            headers=headers,
            timeout=timeout,
        )

        if request.status_code == 403:
            raise errors.PluginError("Authentication error. Please verify that your API key is valid and correct permissions are assigned.")

        return request.json()
