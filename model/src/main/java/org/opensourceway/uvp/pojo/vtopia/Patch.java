package org.opensourceway.uvp.pojo.vtopia;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record Patch(@JsonProperty("package") String pkg, @JsonProperty("fixversion") String fixVersion,
                    @JsonProperty("fix_patch") String fixPatch, @JsonProperty("break_patch") String breakPatch,
                    String source, String branch) {
}
