package org.opensourceway.uvp.pojo.vtopia;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record BaseMetricV3(CvssData cvssV3) {
}