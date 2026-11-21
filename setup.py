# ==============================================================================
# Program: setup.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Packaging and installation configuration for RelayScrub.
#          Defines metadata, package discovery, console script entry points,
#          and dependency specifications (pure standard library, no external dependencies).
# ==============================================================================

# Legacy setuptools entry; pyproject.toml carries the same metadata for modern builds.
from setuptools import setup, find_packages

# Metadata mirrors pyproject.toml. Pure standard library, so install_requires is empty.
setup(
    name="relayscrub",
    version="1.0.0",
    description="Experimental offline, stdlib-only scrubber for secrets and personal data in prompts, plus fencing for untrusted LLM replies.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Ethan-da-Tech-Wizard",
    url="https://github.com/Ethan-da-Tech-Wizard/relayscrub",
    packages=find_packages(include=["relayscrub*"]),
    # Ship the JSON name lists that scrub.py loads at runtime (data/*.json).
    package_data={"relayscrub": ["data/*.json"]},
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[],
    # Console scripts expose each module's main() as a command.
    entry_points={
        "console_scripts": [
            "relayscrub-scrub = relayscrub.scrub:main",
            "relayscrub-inbound = relayscrub.inbound:main",
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
