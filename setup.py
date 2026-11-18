# Program: relayscrub - setup.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Packaging script: tells setuptools the package name, version, entry points and data files so relayscrub can be installed with pip.

"""Packaging and installation configuration for RelayScrub (standard library only, no external dependencies)."""

# setuptools builds and installs Python packages; find_packages locates the package folders.
from setuptools import setup, find_packages

# Describe the project to the installer: metadata, which packages and data files to include, and the command-line tools.
setup(
    name="relayscrub",
    version="1.0.0",
    description="Zero-Dependency, Offline Deterministic Privacy Scrubber & Untrusted LLM Content Fencing Framework for AI Agents.",
    # The README text is shown as the long description on a package page.
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Ethan-da-Tech-Wizard",
    author_email="security@twu.software",
    url="https://github.com/Ethan-da-Tech-Wizard/relayscrub",
    # Include only the relayscrub package(s).
    packages=find_packages(include=["relayscrub*"]),
    # Ship the JSON data files (host names etc.) inside the package.
    package_data={"relayscrub": ["data/*.json"]},
    include_package_data=True,
    # Needs Python 3.8 or newer.
    python_requires=">=3.8",
    # No third-party dependencies.
    install_requires=[],
    # Console commands created on install: relayscrub-scrub runs scrub.main, relayscrub-inbound runs inbound.main.
    entry_points={
        "console_scripts": [
            "relayscrub-scrub = relayscrub.scrub:main",
            "relayscrub-inbound = relayscrub.inbound:main",
        ]
    },
    # Labels used by package indexes (maturity, audience, licences, topic).
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
