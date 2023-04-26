package org.opensourceway.uvp.pojo.vtopia;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record Impact(BaseMetricV3 baseMetricV3, BaseMetricV2 baseMetricV2) {
}
