package org.opensourceway.uvp.pojo.nvd.cpematch;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * See <a href="https://nvd.nist.gov/developers/products">NVD CPE API DOC</a> for details.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class NvdCpeMatchResp {

    /**
     * The maximum number of matchStrings to be returned in a single API response.
     * The default value and maximum allowable limit is 5,000.
     */
    private Integer resultsPerPage;

    /**
     * The index of the first matchString to be returned in the response data.
     */
    private Integer startIndex;

    /**
     * The number of matchStrings that match the request criteria.
     */
    private Integer totalResults;

    /**
     * A list of objects equal to the number of matchStrings returned in the response.
     */
    private List<MatchStringWrapper> matchStrings;

    public Integer getResultsPerPage() {
        return resultsPerPage;
    }

    public Integer getStartIndex() {
        return startIndex;
    }

    public Integer getTotalResults() {
        return totalResults;
    }

    public List<MatchStringWrapper> getMatchStrings() {
        return matchStrings;
    }
}
