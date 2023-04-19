package org.opensourceway.uvp.pojo.nvd.cve;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record CvssData(String version, String vectorString, Double baseScore) {
}
