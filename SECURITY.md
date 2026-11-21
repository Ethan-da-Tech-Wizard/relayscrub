# Security policy

## What relayscrub is, and is not

RelayScrub is an experimental, standard-library Python library that tries to remove likely secrets and personal identifiers from text before it is sent to an LLM, and wraps LLM replies in a fence so they are treated as data. Detection is pattern- and heuristic-based: it can miss secrets, identifiers and injection attempts, and it can flag harmless text. Fencing a reply does not make the reply safe to act on; a human still has to review any command.

It is not audited by any third party. The tests are the author's own, written with AI coding agents. Do not treat it as a security boundary or rely on it as your only control.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**: open this repository's **Security** tab and choose **Report a vulnerability**. That creates a private advisory visible only to the maintainer and to you. Do not open a public issue for a vulnerability, and do not paste real secrets or personal data into any report.

Useful in a report: what you did, what you expected, what happened, and your Python version and OS.

This is a one-person project with no service-level promise; reports are answered as time allows.

Wrong or overstated claims in the README count too. Open a normal issue for those.

## Supported versions

Only the latest commit on the default branch. There are no releases.
