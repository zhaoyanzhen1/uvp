package org.opensourceway.uvp.pojo.response;

import org.opensourceway.uvp.entity.Severity;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.CvssSeverity;

import java.util.ArrayList;
import java.util.List;

/**
 * Response for a search request, which consists of essentials of vulnerabilities.
 */
public class SearchResp {

    private List<SearchRespObj> vulns = new ArrayList<>();

    /**
     * Whether the last page of results.
     */
    private Boolean lastPage;

    public List<SearchRespObj> getVulns() {
        return vulns;
    }

    public void setVulns(List<SearchRespObj> vulns) {
        this.vulns = vulns;
    }

    public Boolean getLastPage() {
        return lastPage;
    }

    public void setLastPage(Boolean lastPage) {
        this.lastPage = lastPage;
    }

    public static class SearchRespObj {

        /**
         * @see Vulnerability#vulnId
         */
        private String vulnId;

        /**
         * @see Vulnerability#summary
         */
        private String summary;

        /**
         * @see Severity#score
         */
        private Double score;

        /**
         * @see Severity#severity
         */
        private CvssSeverity severity;

        /**
         * @see Vulnerability#published
         */
        private String published;

        /**
         * @see Vulnerability#modified
         */
        private String modified;

        /**
         * The list of PURLs that are affected by the vulnerability.
         * The Package URL SHOULD NOT contain version attribute.
         */
        private List<String> affectedPackages;

        /**
         * Whether a fixed version is available.
         */
        private Boolean fixed;

        public String getVulnId() {
            return vulnId;
        }

        public void setVulnId(String vulnId) {
            this.vulnId = vulnId;
        }

        public String getSummary() {
            return summary;
        }

        public void setSummary(String summary) {
            this.summary = summary;
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

        public List<String> getAffectedPackages() {
            return affectedPackages;
        }

        public void setAffectedPackages(List<String> affectedPackages) {
            this.affectedPackages = affectedPackages;
        }

        public Boolean getFixed() {
            return fixed;
        }

        public void setFixed(Boolean fixed) {
            this.fixed = fixed;
        }
    }
}
