# Subscribe to UVP

UVP pushes newly created or updated vulnerabilities by calling the subscriber's REST API.

## Subscriber's REST API Specification

Endpoint: `{your_own_endpoint}`

Request Method: `POST`

Request Body: `json dict with source and osv schema vulnerability`

### Example of request body

```json
{
  "source": "UVP",
  "vuln": {
    "id": "CVE-2023-32996",
    "modified": "2023-05-31T18:41:08.840Z",
    "published": "2023-05-16T17:15:12.027Z",
    "aliases": [
      "GHSA-w88f-j9rc-h7v3"
    ],
    "summary": "Jenkins SAML Single Sign On(SSO) Plugin missing permission checks",
    "details": "A missing permission check in Jenkins SAML Single Sign On(SSO) Plugin 2.0.0 and earlier allows attackers with Overall/Read permission to send an HTTP POST request with JSON body containing attacker-specified content, to miniOrange's API for sending emails.",
    "severity": [
      {
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N"
      }
    ],
    "affected": [
      {
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.0.1"
              }
            ]
          }
        ],
        "versions": [
          "1.0.1",
          "1.0.10",
          "1.0.11",
          "1.0.14",
          "1.0.15",
          "1.0.16",
          "1.0.18",
          "1.0.19",
          "1.0.2",
          "1.0.3",
          "1.0.4",
          "1.0.5",
          "1.0.9",
          "2.0.0"
        ],
        "package": {
          "ecosystem": "Maven",
          "name": "io.jenkins.plugins:miniorange-saml-sp",
          "purl": "pkg:maven/io.jenkins.plugins/miniorange-saml-sp"
        },
        "database_specific": {
          "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2023/05/GHSA-w88f-j9rc-h7v3/GHSA-w88f-j9rc-h7v3.json"
        }
      }
    ],
    "references": [
      {
        "type": "ADVISORY",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32996"
      },
      {
        "type": "WEB",
        "url": "https://www.jenkins.io/security/advisory/2023-05-16/#SECURITY-2994"
      },
      {
        "type": "ADVISORY",
        "url": "https://www.jenkins.io/security/advisory/2023-05-16/#SECURITY-2994"
      }
    ],
    "schema_version": "1.5.0",
    "database_specific": {
      "OSV": {
        "cwe_ids": [],
        "severity": "MODERATE",
        "github_reviewed": true,
        "nvd_published_at": null,
        "github_reviewed_at": "2023-05-17T03:36:15Z"
      }
    }
  }
}
```

---
[Back to the README](../README.md)
