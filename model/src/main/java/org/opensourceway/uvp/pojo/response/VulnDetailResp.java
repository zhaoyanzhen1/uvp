package org.opensourceway.uvp.pojo.response;

import org.opensourceway.uvp.entity.Reference;
import org.opensourceway.uvp.entity.Severity;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.CvssSeverity;

import java.util.List;

/**
 * Response for a vulnerability detail request.
 */
public class VulnDetailResp {

    /**
     * @see Vulnerability#aliases
     */
    private List<String> aliases;

    /**
     * @see Vulnerability#published
     */
    private String published;

    /**
     * @see Vulnerability#modified
     */
    private String modified;

    /**
     * @see Vulnerability#detail
     */
    private String detail;

    /**
     * @see Severity#score
     */
    private Double score;

    /**
     * @see Severity#severity
     */
    private CvssSeverity severity;

    /**
     * @see Severity#vector
     */
    private String vector;

    /**
     * @see Vulnerability#references
     * @see Reference#url
     */
    private List<String> references;

    /**
     * A list of affected packages with their name/PURL, affected versions.
     * @see AffectedPackage
     */
    private List<AffectedPackage> affectedPackages;

    public List<String> getAliases() {
        return aliases;
    }

    public void setAliases(List<String> aliases) {
        this.aliases = aliases;
    }

    public String getPublished() {
        return published;
    }

    public void setPublished(String published) {
        this.published = published;
    }

    public String getModified() {
        return modified;
    }

    public void setModified(String modified) {
        this.modified = modified;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public Double getScore() {
        return score;
    }

    public void setScore(Double score) {
        this.score = score;
    }

    public CvssSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(CvssSeverity severity) {
        this.severity = severity;
    }

    public String getVector() {
        return vector;
    }

    public void setVector(String vector) {
        this.vector = vector;
    }

    public List<String> getReferences() {
        return references;
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }

    public List<AffectedPackage> getAffectedPackages() {
        return affectedPackages;
    }

    public void setAffectedPackages(List<AffectedPackage> affectedPackages) {
        this.affectedPackages = affectedPackages;
    }

    public static class AffectedPackage {

        /**
         * Name or PURL of a package.
         */
        private String pkg;

        /**
         * A list of affected ranges and fixed version.
         * @see AffectedRange
         */
        private List<AffectedRange> affectedRanges;

        /**
         * A list of affected versions.
         */
        private List<String> affectedVersions;

        public String getPkg() {
            return pkg;
        }

        public void setPkg(String pkg) {
            this.pkg = pkg;
        }

        public List<AffectedRange> getAffectedRanges() {
            return affectedRanges;
        }

        public void setAffectedRanges(List<AffectedRange> affectedRanges) {
            this.affectedRanges = affectedRanges;
        }

        public List<String> getAffectedVersions() {
            return affectedVersions;
        }

        public void setAffectedVersions(List<String> affectedVersions) {
            this.affectedVersions = affectedVersions;
        }

        public static class AffectedRange {

            public static final String INTRO_ONLY = ">= %s";

            public static final String INTRO_AND_LAST_AFFECTED = ">= %s, <= %s";

            public static final String INTRO_AND_FIXED = ">= %s, < %s";

            public static final String LAST_AFFECTED_ONLY = "<= %s";

            public static final String FIXED_ONLY = "< %s";

            /**
             * Affected range.
             * <p>For example: ">= 2.0.0, < 2.0.2"</p>
             */
            private String affected;

            /**
             * Fix version.
             * <p>For example: "2.0.2"</p>
             */
            private String fixed;

            public AffectedRange(String affected, String fixed) {
                this.affected = affected;
                this.fixed = fixed;
            }

            public String getAffected() {
                return affected;
            }

            public void setAffected(String affected) {
                this.affected = affected;
            }

            public String getFixed() {
                return fixed;
            }

            public void setFixed(String fixed) {
                this.fixed = fixed;
            }
        }
    }
}
