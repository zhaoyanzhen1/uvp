package org.opensourceway.uvp.pojo.nvd.cpematch;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record MatchStringWrapper(MatchString matchString) {
}
