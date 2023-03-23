package org.opensourceway.uvp.api;

public class Example {
    public static final String PURL_EXAMPLE = "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0";

    public static final String PURL_LIST_EXAMPLE = """
            [
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0"
            ]
            """;

    public static final String OSV_VULN_EXAMPLE = """
            [
                {
                    "id": "GHSA-jfh8-c2jp-5v3q",
                    "modified": "2023-03-12T05:37:05.056138Z",
                    "published": "2021-12-10T00:40:56Z",
                    "aliases": [
                        "CVE-2021-44228"
                    ],
                    "summary": "Remote code injection in Log4j",
                    "details": "# Summary\\n\\nLog4j versions prior to 2.16.0 are subject to a remote code execution vulnerability via the ldap JNDI parser.\\nAs per [Apache's Log4j security guide](https://logging.apache.org/log4j/2.x/security.html): Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.16.0, this behavior has been disabled by default.\\n\\nLog4j version 2.15.0 contained an earlier fix for the vulnerability, but that patch did not disable attacker-controlled JNDI lookups in all situations. For more information, see the `Updated advice for version 2.16.0` section of this advisory.\\n\\n# Impact\\n\\nLogging untrusted or user controlled data with a vulnerable version of Log4J may result in Remote Code Execution (RCE) against your application. This includes untrusted data included in logged errors such as exception traces, authentication failures, and other unexpected vectors of user controlled input. \\n\\n# Affected versions\\n\\nAny Log4J version prior to v2.15.0 is affected to this specific issue.\\n\\nThe v1 branch of Log4J which is considered End Of Life (EOL) is vulnerable to other RCE vectors so the recommendation is to still update to 2.16.0 where possible.\\n\\n## Security releases\\nAdditional backports of this fix have been made available in versions 2.3.1, 2.12.2, and 2.12.3\\n\\n## Affected packages\\nOnly the `org.apache.logging.log4j:log4j-core` package is directly affected by this vulnerability. The `org.apache.logging.log4j:log4j-api` should be kept at the same version as the `org.apache.logging.log4j:log4j-core` package to ensure compatability if in use.\\n\\n# Remediation Advice\\n\\n## Updated advice for version 2.16.0\\n\\nThe Apache Logging Services team provided updated mitigation advice upon the release of version 2.16.0, which [disables JNDI by default and completely removes support for message lookups](https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0).\\nEven in version 2.15.0, lookups used in layouts to provide specific pieces of context information will still recursively resolve, possibly triggering JNDI lookups. This problem is being tracked as [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046). More information is available on the [GitHub Security Advisory for CVE-2021-45046](https://github.com/advisories/GHSA-7rjr-3q55-vv33).\\n\\nUsers who want to avoid attacker-controlled JNDI lookups but cannot upgrade to 2.16.0 must [ensure that no such lookups resolve to attacker-provided data and ensure that the the JndiLookup class is not loaded](https://issues.apache.org/jira/browse/LOG4J2-3221).\\n\\nPlease note that Log4J v1 is End Of Life (EOL) and will not receive patches for this issue. Log4J v1 is also vulnerable to other RCE vectors and we recommend you migrate to Log4J 2.16.0 where possible.\\n\\n",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                        }
                    ],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {
                                            "introduced": "2.13.0"
                                        },
                                        {
                                            "fixed": "2.15.0"
                                        }
                                    ]
                                }
                            ],
                            "versions": [
                                "2.13.0",
                                "2.13.1",
                                "2.13.2",
                                "2.13.3",
                                "2.14.0",
                                "2.14.1"
                            ],
                            "package": {
                                "ecosystem": "Maven",
                                "name": "org.apache.logging.log4j:log4j-core",
                                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"
                            },
                            "database_specific": {
                                "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"
                            }
                        },
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {
                                            "introduced": "0"
                                        },
                                        {
                                            "fixed": "2.3.1"
                                        }
                                    ]
                                }
                            ],
                            "versions": [
                                "2.0",
                                "2.0-alpha1",
                                "2.0-alpha2",
                                "2.0-beta1",
                                "2.0-beta2",
                                "2.0-beta3",
                                "2.0-beta4",
                                "2.0-beta5",
                                "2.0-beta6",
                                "2.0-beta7",
                                "2.0-beta8",
                                "2.0-beta9",
                                "2.0-rc1",
                                "2.0-rc2",
                                "2.0.1",
                                "2.0.2",
                                "2.1",
                                "2.2",
                                "2.3"
                            ],
                            "package": {
                                "ecosystem": "Maven",
                                "name": "org.apache.logging.log4j:log4j-core",
                                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"
                            },
                            "database_specific": {
                                "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"
                            }
                        },
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {
                                            "introduced": "2.4"
                                        },
                                        {
                                            "fixed": "2.12.2"
                                        }
                                    ]
                                }
                            ],
                            "versions": [
                                "2.10.0",
                                "2.11.0",
                                "2.11.1",
                                "2.11.2",
                                "2.12.0",
                                "2.12.1",
                                "2.4",
                                "2.4.1",
                                "2.5",
                                "2.6",
                                "2.6.1",
                                "2.6.2",
                                "2.7",
                                "2.8",
                                "2.8.1",
                                "2.8.2",
                                "2.9.0",
                                "2.9.1"
                            ],
                            "package": {
                                "ecosystem": "Maven",
                                "name": "org.apache.logging.log4j:log4j-core",
                                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"
                            },
                            "database_specific": {
                                "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"
                            }
                        }
                    ],
                    "references": [
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html"
                        },
                        {
                            "type": "ADVISORY",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                        },
                        {
                            "type": "WEB",
                            "url": "https://github.com/apache/logging-log4j2/pull/608"
                        },
                        {
                            "type": "WEB",
                            "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-397453.pdf"
                        },
                        {
                            "type": "WEB",
                            "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf"
                        },
                        {
                            "type": "WEB",
                            "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-661247.pdf"
                        },
                        {
                            "type": "WEB",
                            "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-714170.pdf"
                        },
                        {
                            "type": "ADVISORY",
                            "url": "https://github.com/advisories/GHSA-7rjr-3q55-vv33"
                        },
                        {
                            "type": "PACKAGE",
                            "url": "https://github.com/apache/logging-log4j2"
                        },
                        {
                            "type": "WEB",
                            "url": "https://github.com/cisagov/log4j-affected-db"
                        },
                        {
                            "type": "WEB",
                            "url": "https://github.com/cisagov/log4j-affected-db/blob/develop/SOFTWARE-LIST.md"
                        },
                        {
                            "type": "WEB",
                            "url": "https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228"
                        },
                        {
                            "type": "WEB",
                            "url": "https://github.com/tangxiaofeng7/apache-log4j-poc"
                        },
                        {
                            "type": "WEB",
                            "url": "https://issues.apache.org/jira/browse/LOG4J2-3198"
                        },
                        {
                            "type": "WEB",
                            "url": "https://issues.apache.org/jira/browse/LOG4J2-3201"
                        },
                        {
                            "type": "WEB",
                            "url": "https://issues.apache.org/jira/browse/LOG4J2-3214"
                        },
                        {
                            "type": "WEB",
                            "url": "https://issues.apache.org/jira/browse/LOG4J2-3221"
                        },
                        {
                            "type": "WEB",
                            "url": "https://lists.debian.org/debian-lts-announce/2021/12/msg00007.html"
                        },
                        {
                            "type": "WEB",
                            "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M5CSVUNV4HWZZXGOKNSK6L7RPM7BOKIB/"
                        },
                        {
                            "type": "WEB",
                            "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU57UJDCFIASIO35GC55JMKSRXJMCDFM/"
                        },
                        {
                            "type": "WEB",
                            "url": "https://logging.apache.org/log4j/2.x/changes-report.html#a2.15.0"
                        },
                        {
                            "type": "WEB",
                            "url": "https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup"
                        },
                        {
                            "type": "WEB",
                            "url": "https://logging.apache.org/log4j/2.x/manual/migration.html"
                        },
                        {
                            "type": "WEB",
                            "url": "https://logging.apache.org/log4j/2.x/security.html"
                        },
                        {
                            "type": "WEB",
                            "url": "https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/"
                        },
                        {
                            "type": "WEB",
                            "url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032"
                        },
                        {
                            "type": "WEB",
                            "url": "https://security.netapp.com/advisory/ntap-20211210-0007/"
                        },
                        {
                            "type": "WEB",
                            "url": "https://support.apple.com/kb/HT213189"
                        },
                        {
                            "type": "WEB",
                            "url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd"
                        },
                        {
                            "type": "WEB",
                            "url": "https://twitter.com/kurtseifried/status/1469345530182455296"
                        },
                        {
                            "type": "WEB",
                            "url": "https://www.bentley.com/en/common-vulnerability-exposure/be-2022-0001"
                        },
                        {
                            "type": "WEB",
                            "url": "https://www.debian.org/security/2021/dsa-5020"
                        },
                        {
                            "type": "WEB",
                            "url": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00646.html"
                        },
                        {
                            "type": "WEB",
                            "url": "https://www.kb.cert.org/vuls/id/930724"
                        },
                        {
                            "type": "WEB",
                            "url": "https://www.nu11secur1ty.com/2021/12/cve-2021-44228.html"
                        },
                        {
                            "type": "WEB",
                            "url": "https://www.oracle.com/security-alerts/alert-cve-2021-44228.html"
                        },
                        {
                            "type": "WEB",
                            "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
                        },
                        {
                            "type": "WEB",
                            "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165281/Log4j2-Log4Shell-Regexes.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165282/Log4j-Payload-Generator.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165306/L4sh-Log4j-Remote-Code-Execution.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165307/Log4j-Remote-Code-Execution-Word-Bypassing.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165311/log4j-scan-Extensive-Scanner.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165371/VMware-Security-Advisory-2021-0028.4.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/167794/Open-Xchange-App-Suite-7.10.x-Cross-Site-Scripting-Command-Injection.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://packetstormsecurity.com/files/167917/MobileIron-Log4Shell-Remote-Command-Execution.html"
                        },
                        {
                            "type": "WEB",
                            "url": "http://seclists.org/fulldisclosure/2022/Dec/2"
                        },
                        {
                            "type": "WEB",
                            "url": "http://seclists.org/fulldisclosure/2022/Jul/11"
                        },
                        {
                            "type": "WEB",
                            "url": "http://seclists.org/fulldisclosure/2022/Mar/23"
                        },
                        {
                            "type": "WEB",
                            "url": "http://www.openwall.com/lists/oss-security/2021/12/10/1"
                        },
                        {
                            "type": "WEB",
                            "url": "http://www.openwall.com/lists/oss-security/2021/12/10/2"
                        },
                        {
                            "type": "WEB",
                            "url": "http://www.openwall.com/lists/oss-security/2021/12/10/3"
                        },
                        {
                            "type": "WEB",
                            "url": "http://www.openwall.com/lists/oss-security/2021/12/13/1"
                        },
                        {
                            "type": "WEB",
                            "url": "http://www.openwall.com/lists/oss-security/2021/12/13/2"
                        },
                        {
                            "type": "WEB",
                            "url": "http://www.openwall.com/lists/oss-security/2021/12/14/4"
                        },
                        {
                            "type": "WEB",
                            "url": "http://www.openwall.com/lists/oss-security/2021/12/15/3"
                        }
                    ],
                    "schema_version": "1.3.0",
                    "database_specific": {
                        "cwe_ids": [
                            "CWE-20",
                            "CWE-400",
                            "CWE-502",
                            "CWE-917"
                        ],
                        "severity": "CRITICAL",
                        "github_reviewed": true,
                        "nvd_published_at": "2021-12-10T10:15:00Z",
                        "github_reviewed_at": "2021-12-10T00:40:41Z"
                    }
                }
            ]
            """;

    public static final String PKG_VULNS_EXAMPLE = """
            [
                {
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0",
                    "vulns": [
                        {
                            "id": "GHSA-jfh8-c2jp-5v3q",
                            "modified": "2023-03-12T05:37:05.056138Z",
                            "published": "2021-12-10T00:40:56Z",
                            "aliases": [
                                "CVE-2021-44228"
                            ],
                            "summary": "Remote code injection in Log4j",
                            "details": "# Summary\\n\\nLog4j versions prior to 2.16.0 are subject to a remote code execution vulnerability via the ldap JNDI parser.\\nAs per [Apache's Log4j security guide](https://logging.apache.org/log4j/2.x/security.html): Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.16.0, this behavior has been disabled by default.\\n\\nLog4j version 2.15.0 contained an earlier fix for the vulnerability, but that patch did not disable attacker-controlled JNDI lookups in all situations. For more information, see the `Updated advice for version 2.16.0` section of this advisory.\\n\\n# Impact\\n\\nLogging untrusted or user controlled data with a vulnerable version of Log4J may result in Remote Code Execution (RCE) against your application. This includes untrusted data included in logged errors such as exception traces, authentication failures, and other unexpected vectors of user controlled input. \\n\\n# Affected versions\\n\\nAny Log4J version prior to v2.15.0 is affected to this specific issue.\\n\\nThe v1 branch of Log4J which is considered End Of Life (EOL) is vulnerable to other RCE vectors so the recommendation is to still update to 2.16.0 where possible.\\n\\n## Security releases\\nAdditional backports of this fix have been made available in versions 2.3.1, 2.12.2, and 2.12.3\\n\\n## Affected packages\\nOnly the `org.apache.logging.log4j:log4j-core` package is directly affected by this vulnerability. The `org.apache.logging.log4j:log4j-api` should be kept at the same version as the `org.apache.logging.log4j:log4j-core` package to ensure compatability if in use.\\n\\n# Remediation Advice\\n\\n## Updated advice for version 2.16.0\\n\\nThe Apache Logging Services team provided updated mitigation advice upon the release of version 2.16.0, which [disables JNDI by default and completely removes support for message lookups](https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0).\\nEven in version 2.15.0, lookups used in layouts to provide specific pieces of context information will still recursively resolve, possibly triggering JNDI lookups. This problem is being tracked as [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046). More information is available on the [GitHub Security Advisory for CVE-2021-45046](https://github.com/advisories/GHSA-7rjr-3q55-vv33).\\n\\nUsers who want to avoid attacker-controlled JNDI lookups but cannot upgrade to 2.16.0 must [ensure that no such lookups resolve to attacker-provided data and ensure that the the JndiLookup class is not loaded](https://issues.apache.org/jira/browse/LOG4J2-3221).\\n\\nPlease note that Log4J v1 is End Of Life (EOL) and will not receive patches for this issue. Log4J v1 is also vulnerable to other RCE vectors and we recommend you migrate to Log4J 2.16.0 where possible.\\n\\n",
                            "severity": [
                                {
                                    "type": "CVSS_V3",
                                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                                }
                            ],
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {
                                                    "introduced": "2.13.0"
                                                },
                                                {
                                                    "fixed": "2.15.0"
                                                }
                                            ]
                                        }
                                    ],
                                    "versions": [
                                        "2.13.0",
                                        "2.13.1",
                                        "2.13.2",
                                        "2.13.3",
                                        "2.14.0",
                                        "2.14.1"
                                    ],
                                    "package": {
                                        "ecosystem": "Maven",
                                        "name": "org.apache.logging.log4j:log4j-core",
                                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"
                                    },
                                    "database_specific": {
                                        "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"
                                    }
                                },
                                {
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {
                                                    "introduced": "0"
                                                },
                                                {
                                                    "fixed": "2.3.1"
                                                }
                                            ]
                                        }
                                    ],
                                    "versions": [
                                        "2.0",
                                        "2.0-alpha1",
                                        "2.0-alpha2",
                                        "2.0-beta1",
                                        "2.0-beta2",
                                        "2.0-beta3",
                                        "2.0-beta4",
                                        "2.0-beta5",
                                        "2.0-beta6",
                                        "2.0-beta7",
                                        "2.0-beta8",
                                        "2.0-beta9",
                                        "2.0-rc1",
                                        "2.0-rc2",
                                        "2.0.1",
                                        "2.0.2",
                                        "2.1",
                                        "2.2",
                                        "2.3"
                                    ],
                                    "package": {
                                        "ecosystem": "Maven",
                                        "name": "org.apache.logging.log4j:log4j-core",
                                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"
                                    },
                                    "database_specific": {
                                        "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"
                                    }
                                },
                                {
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {
                                                    "introduced": "2.4"
                                                },
                                                {
                                                    "fixed": "2.12.2"
                                                }
                                            ]
                                        }
                                    ],
                                    "versions": [
                                        "2.10.0",
                                        "2.11.0",
                                        "2.11.1",
                                        "2.11.2",
                                        "2.12.0",
                                        "2.12.1",
                                        "2.4",
                                        "2.4.1",
                                        "2.5",
                                        "2.6",
                                        "2.6.1",
                                        "2.6.2",
                                        "2.7",
                                        "2.8",
                                        "2.8.1",
                                        "2.8.2",
                                        "2.9.0",
                                        "2.9.1"
                                    ],
                                    "package": {
                                        "ecosystem": "Maven",
                                        "name": "org.apache.logging.log4j:log4j-core",
                                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"
                                    },
                                    "database_specific": {
                                        "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"
                                    }
                                }
                            ],
                            "references": [
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html"
                                },
                                {
                                    "type": "ADVISORY",
                                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://github.com/apache/logging-log4j2/pull/608"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-397453.pdf"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-661247.pdf"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-714170.pdf"
                                },
                                {
                                    "type": "ADVISORY",
                                    "url": "https://github.com/advisories/GHSA-7rjr-3q55-vv33"
                                },
                                {
                                    "type": "PACKAGE",
                                    "url": "https://github.com/apache/logging-log4j2"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://github.com/cisagov/log4j-affected-db"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://github.com/cisagov/log4j-affected-db/blob/develop/SOFTWARE-LIST.md"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://github.com/tangxiaofeng7/apache-log4j-poc"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://issues.apache.org/jira/browse/LOG4J2-3198"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://issues.apache.org/jira/browse/LOG4J2-3201"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://issues.apache.org/jira/browse/LOG4J2-3214"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://issues.apache.org/jira/browse/LOG4J2-3221"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://lists.debian.org/debian-lts-announce/2021/12/msg00007.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M5CSVUNV4HWZZXGOKNSK6L7RPM7BOKIB/"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU57UJDCFIASIO35GC55JMKSRXJMCDFM/"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://logging.apache.org/log4j/2.x/changes-report.html#a2.15.0"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://logging.apache.org/log4j/2.x/manual/migration.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://logging.apache.org/log4j/2.x/security.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://security.netapp.com/advisory/ntap-20211210-0007/"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://support.apple.com/kb/HT213189"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://twitter.com/kurtseifried/status/1469345530182455296"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://www.bentley.com/en/common-vulnerability-exposure/be-2022-0001"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://www.debian.org/security/2021/dsa-5020"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00646.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://www.kb.cert.org/vuls/id/930724"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://www.nu11secur1ty.com/2021/12/cve-2021-44228.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://www.oracle.com/security-alerts/alert-cve-2021-44228.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://www.oracle.com/security-alerts/cpuapr2022.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "https://www.oracle.com/security-alerts/cpujan2022.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165281/Log4j2-Log4Shell-Regexes.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165282/Log4j-Payload-Generator.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165306/L4sh-Log4j-Remote-Code-Execution.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165307/Log4j-Remote-Code-Execution-Word-Bypassing.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165311/log4j-scan-Extensive-Scanner.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165371/VMware-Security-Advisory-2021-0028.4.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/167794/Open-Xchange-App-Suite-7.10.x-Cross-Site-Scripting-Command-Injection.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://packetstormsecurity.com/files/167917/MobileIron-Log4Shell-Remote-Command-Execution.html"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://seclists.org/fulldisclosure/2022/Dec/2"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://seclists.org/fulldisclosure/2022/Jul/11"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://seclists.org/fulldisclosure/2022/Mar/23"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://www.openwall.com/lists/oss-security/2021/12/10/1"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://www.openwall.com/lists/oss-security/2021/12/10/2"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://www.openwall.com/lists/oss-security/2021/12/10/3"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://www.openwall.com/lists/oss-security/2021/12/13/1"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://www.openwall.com/lists/oss-security/2021/12/13/2"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://www.openwall.com/lists/oss-security/2021/12/14/4"
                                },
                                {
                                    "type": "WEB",
                                    "url": "http://www.openwall.com/lists/oss-security/2021/12/15/3"
                                }
                            ],
                            "schema_version": "1.3.0",
                            "database_specific": {
                                "cwe_ids": [
                                    "CWE-20",
                                    "CWE-400",
                                    "CWE-502",
                                    "CWE-917"
                                ],
                                "severity": "CRITICAL",
                                "github_reviewed": true,
                                "nvd_published_at": "2021-12-10T10:15:00Z",
                                "github_reviewed_at": "2021-12-10T00:40:41Z"
                            }
                        }
                    ]
                }
            ]
            """;

    public static final String ERROR_INVALID_PURL_EXAMPLE = """
            {
                "code": 2,
                "message": "Invalid purl: <some_invalid_purl>"
            }
            """;

    public static final String ERROR_INVALID_PURL_LIST_EXAMPLE = """
            {
                "code": 2,
                "message": "Invalid purls: [some_invalid_purl, another_invalid_purl]"
            }
            """;

    public static final String ERROR_INTERNAL_EXAMPLE = """
            {
                "code": 1,
                "message": "Unknown error"
            }
            """;

    public static final String SEARCH_REQUEST_EXAMPLE = """
            {
                "keyword": "log4j",
                "page": 0,
                "size": 10
            }
            """;

    public static final String SEARCH_RESP_EXAMPLE = """
            {
                "vulns": [
                    {
                        "vulnId": "GHSA-2qrg-x229-3v8q",
                        "summary": "Deserialization of Untrusted Data in Log4j",
                        "score": 9.8,
                        "severity": "CRITICAL",
                        "published": "2020-01-06T18:43:49Z",
                        "modified": "2023-03-22T06:00:36.456513Z",
                        "affectedPackages": [
                            "pkg:maven/log4j/log4j"
                        ],
                        "fixed": false
                    },
                    {
                        "vulnId": "GHSA-fp5r-v3w9-4333",
                        "summary": "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data",
                        "score": 8.1,
                        "severity": "HIGH",
                        "published": "2021-12-14T19:49:31Z",
                        "modified": "2023-03-16T05:23:12.349613Z",
                        "affectedPackages": [
                            "pkg:maven/log4j/log4j"
                        ],
                        "fixed": false
                    },
                    {
                        "vulnId": "GHSA-vp98-w2p3-mv35",
                        "summary": "Apache Log4j 1.x (EOL) allows Denial of Service (DoS)",
                        "score": 7.5,
                        "severity": "HIGH",
                        "published": "2023-03-10T15:30:43Z",
                        "modified": "2023-03-15T19:22:24.842697Z",
                        "affectedPackages": [
                            "pkg:maven/org.apache.logging.log4j/log4j-core"
                        ],
                        "fixed": true
                    },
                    {
                        "vulnId": "GHSA-f7vh-qwp3-x37m",
                        "summary": "Deserialization of Untrusted Data in Apache Log4j",
                        "score": 9.8,
                        "severity": "CRITICAL",
                        "published": "2022-01-19T00:01:15Z",
                        "modified": "2023-03-15T05:41:04.378570Z",
                        "affectedPackages": [
                            "pkg:maven/log4j/log4j"
                        ],
                        "fixed": false
                    },
                    {
                        "vulnId": "GHSA-w9p3-5cr8-m3jj",
                        "summary": "Deserialization of Untrusted Data in Log4j 1.x",
                        "score": 8.8,
                        "severity": "HIGH",
                        "published": "2022-01-21T23:27:14Z",
                        "modified": "2023-03-14T05:48:41.908344Z",
                        "affectedPackages": [
                            "pkg:maven/log4j/log4j"
                        ],
                        "fixed": false
                    },
                    {
                        "vulnId": "GHSA-65fg-84f6-3jq3",
                        "summary": "SQL Injection in Log4j 1.2.x",
                        "score": 9.8,
                        "severity": "CRITICAL",
                        "published": "2022-01-21T23:26:47Z",
                        "modified": "2023-03-14T05:43:56.927766Z",
                        "affectedPackages": [
                            "pkg:maven/log4j/log4j"
                        ],
                        "fixed": false
                    },
                    {
                        "vulnId": "GHSA-jfh8-c2jp-5v3q",
                        "summary": "Remote code injection in Log4j",
                        "score": 10.0,
                        "severity": "CRITICAL",
                        "published": "2021-12-10T00:40:56Z",
                        "modified": "2023-03-12T05:37:05.056138Z",
                        "affectedPackages": [
                            "pkg:maven/org.apache.logging.log4j/log4j-core"
                        ],
                        "fixed": true
                    },
                    {
                        "vulnId": "GHSA-xxfh-x98p-j8fr",
                        "summary": "Remote code injection in Log4j (through pax-logging-log4j2)",
                        "score": null,
                        "severity": null,
                        "published": "2021-12-10T20:15:37Z",
                        "modified": "2023-03-12T05:30:48.812460Z",
                        "affectedPackages": [
                            "pkg:maven/org.ops4j.pax.logging/pax-logging-log4j2"
                        ],
                        "fixed": true
                    },
                    {
                        "vulnId": "GHSA-vwqq-5vrc-xw9h",
                        "summary": "Improper validation of certificate with host mismatch in Apache Log4j SMTP appender",
                        "score": 3.7,
                        "severity": "LOW",
                        "published": "2020-06-05T14:15:51Z",
                        "modified": "2023-03-11T05:41:49.563071Z",
                        "affectedPackages": [
                            "pkg:maven/org.apache.logging.log4j/log4j",
                            "pkg:maven/org.apache.logging.log4j/log4j-core"
                        ],
                        "fixed": true
                    },
                    {
                        "vulnId": "GHSA-fxph-q3j8-mv87",
                        "summary": "Deserialization of Untrusted Data in Log4j",
                        "score": 9.8,
                        "severity": "CRITICAL",
                        "published": "2020-01-06T18:43:38Z",
                        "modified": "2023-03-11T05:40:41.259948Z",
                        "affectedPackages": [
                            "pkg:maven/org.apache.logging.log4j/log4j",
                            "pkg:maven/org.apache.logging.log4j/log4j-core"
                        ],
                        "fixed": true
                    }
                ],
                "lastPage": false
            }
            """;

    public static final String ERROR_ILLEGAL_ARGUMENT_EXAMPLE = """
            {
                "code": 4,
                "message": "Page index must not be less than zero"
            }
            """;

    public static final String VULN_ID_EXAMPLE = "GHSA-jfh8-c2jp-5v3q";

    public static final String VULN_DETAIL_EXAMPLE = """
            {
                "aliases": [
                    "CVE-2021-44228"
                ],
                "published": "2021-12-10T00:40:56Z",
                "modified": "2023-03-12T05:37:05.056138Z",
                "detail": "# Summary\\n\\nLog4j versions prior to 2.16.0 are subject to a remote code execution vulnerability via the ldap JNDI parser.\\nAs per [Apache's Log4j security guide](https://logging.apache.org/log4j/2.x/security.html): Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.16.0, this behavior has been disabled by default.\\n\\nLog4j version 2.15.0 contained an earlier fix for the vulnerability, but that patch did not disable attacker-controlled JNDI lookups in all situations. For more information, see the `Updated advice for version 2.16.0` section of this advisory.\\n\\n# Impact\\n\\nLogging untrusted or user controlled data with a vulnerable version of Log4J may result in Remote Code Execution (RCE) against your application. This includes untrusted data included in logged errors such as exception traces, authentication failures, and other unexpected vectors of user controlled input. \\n\\n# Affected versions\\n\\nAny Log4J version prior to v2.15.0 is affected to this specific issue.\\n\\nThe v1 branch of Log4J which is considered End Of Life (EOL) is vulnerable to other RCE vectors so the recommendation is to still update to 2.16.0 where possible.\\n\\n## Security releases\\nAdditional backports of this fix have been made available in versions 2.3.1, 2.12.2, and 2.12.3\\n\\n## Affected packages\\nOnly the `org.apache.logging.log4j:log4j-core` package is directly affected by this vulnerability. The `org.apache.logging.log4j:log4j-api` should be kept at the same version as the `org.apache.logging.log4j:log4j-core` package to ensure compatability if in use.\\n\\n# Remediation Advice\\n\\n## Updated advice for version 2.16.0\\n\\nThe Apache Logging Services team provided updated mitigation advice upon the release of version 2.16.0, which [disables JNDI by default and completely removes support for message lookups](https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0).\\nEven in version 2.15.0, lookups used in layouts to provide specific pieces of context information will still recursively resolve, possibly triggering JNDI lookups. This problem is being tracked as [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046). More information is available on the [GitHub Security Advisory for CVE-2021-45046](https://github.com/advisories/GHSA-7rjr-3q55-vv33).\\n\\nUsers who want to avoid attacker-controlled JNDI lookups but cannot upgrade to 2.16.0 must [ensure that no such lookups resolve to attacker-provided data and ensure that the the JndiLookup class is not loaded](https://issues.apache.org/jira/browse/LOG4J2-3221).\\n\\nPlease note that Log4J v1 is End Of Life (EOL) and will not receive patches for this issue. Log4J v1 is also vulnerable to other RCE vectors and we recommend you migrate to Log4J 2.16.0 where possible.\\n\\n",
                "score": 10.0,
                "severity": "CRITICAL",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "https://github.com/apache/logging-log4j2/pull/608",
                    "https://cert-portal.siemens.com/productcert/pdf/ssa-397453.pdf",
                    "https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf",
                    "https://cert-portal.siemens.com/productcert/pdf/ssa-661247.pdf",
                    "https://cert-portal.siemens.com/productcert/pdf/ssa-714170.pdf",
                    "https://github.com/advisories/GHSA-7rjr-3q55-vv33",
                    "https://github.com/apache/logging-log4j2",
                    "https://github.com/cisagov/log4j-affected-db",
                    "https://github.com/cisagov/log4j-affected-db/blob/develop/SOFTWARE-LIST.md",
                    "https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228",
                    "https://github.com/tangxiaofeng7/apache-log4j-poc",
                    "https://issues.apache.org/jira/browse/LOG4J2-3198",
                    "https://issues.apache.org/jira/browse/LOG4J2-3201",
                    "https://issues.apache.org/jira/browse/LOG4J2-3214",
                    "https://issues.apache.org/jira/browse/LOG4J2-3221",
                    "https://lists.debian.org/debian-lts-announce/2021/12/msg00007.html",
                    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M5CSVUNV4HWZZXGOKNSK6L7RPM7BOKIB/",
                    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU57UJDCFIASIO35GC55JMKSRXJMCDFM/",
                    "https://logging.apache.org/log4j/2.x/changes-report.html#a2.15.0",
                    "https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup",
                    "https://logging.apache.org/log4j/2.x/manual/migration.html",
                    "https://logging.apache.org/log4j/2.x/security.html",
                    "https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/",
                    "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032",
                    "https://security.netapp.com/advisory/ntap-20211210-0007/",
                    "https://support.apple.com/kb/HT213189",
                    "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd",
                    "https://twitter.com/kurtseifried/status/1469345530182455296",
                    "https://www.bentley.com/en/common-vulnerability-exposure/be-2022-0001",
                    "https://www.debian.org/security/2021/dsa-5020",
                    "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00646.html",
                    "https://www.kb.cert.org/vuls/id/930724",
                    "https://www.nu11secur1ty.com/2021/12/cve-2021-44228.html",
                    "https://www.oracle.com/security-alerts/alert-cve-2021-44228.html",
                    "https://www.oracle.com/security-alerts/cpuapr2022.html",
                    "https://www.oracle.com/security-alerts/cpujan2022.html",
                    "http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html",
                    "http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html",
                    "http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html",
                    "http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html",
                    "http://packetstormsecurity.com/files/165281/Log4j2-Log4Shell-Regexes.html",
                    "http://packetstormsecurity.com/files/165282/Log4j-Payload-Generator.html",
                    "http://packetstormsecurity.com/files/165306/L4sh-Log4j-Remote-Code-Execution.html",
                    "http://packetstormsecurity.com/files/165307/Log4j-Remote-Code-Execution-Word-Bypassing.html",
                    "http://packetstormsecurity.com/files/165311/log4j-scan-Extensive-Scanner.html",
                    "http://packetstormsecurity.com/files/165371/VMware-Security-Advisory-2021-0028.4.html",
                    "http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html",
                    "http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html",
                    "http://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html",
                    "http://packetstormsecurity.com/files/167794/Open-Xchange-App-Suite-7.10.x-Cross-Site-Scripting-Command-Injection.html",
                    "http://packetstormsecurity.com/files/167917/MobileIron-Log4Shell-Remote-Command-Execution.html",
                    "http://seclists.org/fulldisclosure/2022/Dec/2",
                    "http://seclists.org/fulldisclosure/2022/Jul/11",
                    "http://seclists.org/fulldisclosure/2022/Mar/23",
                    "http://www.openwall.com/lists/oss-security/2021/12/10/1",
                    "http://www.openwall.com/lists/oss-security/2021/12/10/2",
                    "http://www.openwall.com/lists/oss-security/2021/12/10/3",
                    "http://www.openwall.com/lists/oss-security/2021/12/13/1",
                    "http://www.openwall.com/lists/oss-security/2021/12/13/2",
                    "http://www.openwall.com/lists/oss-security/2021/12/14/4",
                    "http://www.openwall.com/lists/oss-security/2021/12/15/3"
                ],
                "affectedPackages": [
                    {
                        "pkg": "pkg:maven/org.apache.logging.log4j/log4j-core",
                        "affectedRanges": [
                            {
                                "affected": ">= 2.13.0, < 2.15.0",
                                "fixed": "2.15.0"
                            }
                        ],
                        "affectedVersions": [
                            "2.13.0",
                            "2.13.1",
                            "2.13.2",
                            "2.13.3",
                            "2.14.0",
                            "2.14.1"
                        ]
                    },
                    {
                        "pkg": "pkg:maven/org.apache.logging.log4j/log4j-core",
                        "affectedRanges": [
                            {
                                "affected": "< 2.3.1",
                                "fixed": "2.3.1"
                            }
                        ],
                        "affectedVersions": [
                            "2.0",
                            "2.0-alpha1",
                            "2.0-alpha2",
                            "2.0-beta1",
                            "2.0-beta2",
                            "2.0-beta3",
                            "2.0-beta4",
                            "2.0-beta5",
                            "2.0-beta6",
                            "2.0-beta7",
                            "2.0-beta8",
                            "2.0-beta9",
                            "2.0-rc1",
                            "2.0-rc2",
                            "2.0.1",
                            "2.0.2",
                            "2.1",
                            "2.2",
                            "2.3"
                        ]
                    },
                    {
                        "pkg": "pkg:maven/org.apache.logging.log4j/log4j-core",
                        "affectedRanges": [
                            {
                                "affected": ">= 2.4, < 2.12.2",
                                "fixed": "2.12.2"
                            }
                        ],
                        "affectedVersions": [
                            "2.10.0",
                            "2.11.0",
                            "2.11.1",
                            "2.11.2",
                            "2.12.0",
                            "2.12.1",
                            "2.4",
                            "2.4.1",
                            "2.5",
                            "2.6",
                            "2.6.1",
                            "2.6.2",
                            "2.7",
                            "2.8",
                            "2.8.1",
                            "2.8.2",
                            "2.9.0",
                            "2.9.1"
                        ]
                    }
                ]
            }
            """;

    public static final String INVALID_VULN_DETAIL_EXAMPLE = """
            {
                "code": 5,
                "message": "Invalid vulnerability ID: <CVE-2021-44228>"
            }
            """;
}
