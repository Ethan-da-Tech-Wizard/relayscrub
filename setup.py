# ==============================================================================
# Program: setup.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Packaging and installation configuration for RelayScrub.
#          Defines metadata, package discovery, console script entry points,
#          and dependency specifications (pure standard library, 0 external dependencies).
# ==============================================================================

from setuptools import setup, find_packages

setup(
    name="relayscrub",
    version="1.0.0",
    description="Zero-Dependency, Offline Deterministic Privacy Scrubber & Untrusted LLM Content Fencing Framework for AI Agents.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Ethan-da-Tech-Wizard",
    author_email="security@twu.software",
    url="https://github.com/Ethan-da-Tech-Wizard/relayscrub",
    packages=find_packages(include=["relayscrub*"]),
    package_data={"relayscrub": ["data/*.json"]},
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "relayscrub-scrub = relayscrub.scrub:main",
            "relayscrub-inbound = relayscrub.inbound:main",
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
