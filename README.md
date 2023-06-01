[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://raw.githubusercontent.com/opensourceways/uvp/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/opensourceways/uvp/badge)](https://api.securityscorecards.dev/projects/github.com/opensourceways/uvp)
[![CodeQL](https://github.com/opensourceways/uvp/actions/workflows/codeql.yml/badge.svg)](https://github.com/opensourceways/uvp/actions/workflows/codeql.yml)
[![Java CI with Gradle](https://github.com/opensourceways/uvp/actions/workflows/gradle.yml/badge.svg)](https://github.com/opensourceways/uvp/actions/workflows/gradle.yml)
[![Renovate enabled](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com/)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

# Welcome to the UVP Project

UVP is a **U**nified **V**ulnerability **P**latform about vulnerabilities that affect open source software.
It's written in Java 17 and built with Gradle.

# Table of Contents

- [Introduction](#uvp---unified-vulnerability-platform)
    - [Architecture](docs/architecture.md)
    - [Data Model](docs/data-model.md)
    - [Integrated Vulnerability Databases](#integrated-vulnerability-databases)
- [Deployment](docs/deployment.md)
    - [Config Vulnerability Source](docs/config-vuln-source.md)
- [Using UVP](#using-uvp)
    - [Viewing the Website](#viewing-the-website)
    - [Using the API](#using-the-api)
    - [Subscription](docs/subscription.md)

# UVP - Unified Vulnerability Platform

UVP is a unified vulnerability platform that provides open source software vulnerability retrieval
and diagnosis service for projects.

Through periodical aggregation of multiple vulnerability databases, UVP provides timely vulnerability information.
Additionally, with heuristic policies, UVP tries to avoid false positives and false negatives.

# Integrated Open Source Vulnerability Databases

* [OSV](https://osv.dev)
* [OSS Index](https://ossindex.sonatype.org)
* [NVD](https://nvd.nist.gov)

# Using UVP

## Viewing the Website

TODO

## Using the API

TODO
