package org.opensourceway.uvp.pojo.nvd.cpematch;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record MatchString(String matchCriteriaId, MatchStringStatus status, List<MatchCpe> matches) {
}
