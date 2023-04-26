package org.opensourceway.uvp.pojo.vtopia;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record VtopiaRespBody(Integer total, List<VtopiaVulnerability> list) {
}
