package org.opensourceway.uvp.pojo.nvd.cve;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdCveWrapper(NvdCve cve) {
}
