package org.opensourceway.uvp.pojo.nvd.cve;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record Reference(String url, List<NvdReferenceTag> tags) {
}
