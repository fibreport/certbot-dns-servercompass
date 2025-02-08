from setuptools import find_packages
from setuptools import setup

version = "1.0.0"

install_requires = [
    "acme>=3.1.0",
    "certbot>=3.1.0",
    "setuptools",
    "requests",
]

docs_extras = [
    "Sphinx>=1.0",  # autodoc_member_order = 'bysource', autodoc_default_flags
    "sphinx_rtd_theme",
]

test_extras = [
    "pytest",
]

setup(
    name="certbot-dns-servercompass",
    version=version,
    description="servercompass.com DNS Authenticator plugin for Certbot",
    url="https://github.com/fibreport/certbot-dns-servercompass",
    author="fibreport UG (haftungsbeschränkt)",
    author_email="rnd@fibreport.com",
    license="Apache License 2.0",
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        "docs": docs_extras,
        "test": test_extras,
    },
    entry_points={"certbot.plugins": ["dns-servercompass = certbot_dns_servercompass.dns_servercompass:Authenticator"]},
    test_suite="certbot_dns_servercompass",
)
