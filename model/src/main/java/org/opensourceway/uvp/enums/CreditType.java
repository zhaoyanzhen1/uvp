package org.opensourceway.uvp.enums;

public enum CreditType {
    /**
     * Identified the vulnerability.
     */
    FINDER,

    /**
     * Notified the vendor of the vulnerability to a CNA.
     */
    REPORTER,

    /**
     * Validated the vulnerability to ensure accuracy or severity.
     */
    ANALYST,

    /**
     * Facilitated the coordinated response process.
     */
    COORDINATOR,

    /**
     * Prepared a code change or other remediation plans.
     */
    REMEDIATION_DEVELOPER,

    /**
     * Reviewed vulnerability remediation plans or code changes for effectiveness and completeness.
     */
    REMEDIATION_REVIEWER,

    /**
     * Tested and verified the vulnerability or its remediation.
     */
    REMEDIATION_VERIFIER,

    /**
     * Names of tools used in vulnerability discovery or identification.
     */
    TOOL,

    /**
     * Supported the vulnerability identification or remediation activities.
     */
    SPONSOR,

    /**
     * Any other type or role that does not fall under the categories described above.
     */
    OTHER,
}
