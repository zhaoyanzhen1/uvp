package org.opensourceway.uvp.enums;

public enum ReferenceType {
    /**
     * A published security advisory for the vulnerability.
     */
    ADVISORY,

    /**
     * An article or blog post describing the vulnerability.
     */
    ARTICLE,

    /**
     * A tool, script, scanner, or other mechanism that allows for
     * detection of the vulnerability in production environments. e.g. YARA rules,
     * hashes, virus signature, or other scanners.
     */
    DETECTION,

    /**
     * A social media discussion regarding the vulnerability, e.g.
     * a Twitter, Mastodon, Hacker News, or Reddit thread.
     */
    DISCUSSION,

    /**
     * A report, typically on a bug or issue tracker, of the vulnerability.
     */
    REPORT,

    /**
     * A source code browser link to the fix (e.g., a GitHub commit) Note that the fix type is meant for
     * viewing by people using web browsers.
     */
    FIX,

    /**
     * A source code browser link to the introduction of the vulnerability
     * (e.g., a GitHub commit) Note that the `introduced` type is meant for viewing by people using
     * web browsers. Programs interested in analyzing the exact commit range would do better
     * to use the `GIT`-typed `affected[].ranges` entries.
     */
    INTRODUCED,

    /**
     * A home web page for the package.
     */
    PACKAGE,

    /**
     * A demonstration of the validity of a vulnerability claim, e.g. app.any.run replaying the exploitation of the vulnerability.
     */
    EVIDENCE,

    /**
     * A web page of some unspecified kind.
     */
    WEB
}
