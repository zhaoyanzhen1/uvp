package org.opensourceway.uvp.clients.nvd;

import org.opensourceway.uvp.clients.Nvd;
import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.pojo.nvd.cpematch.NvdCpeMatchResp;
import org.opensourceway.uvp.pojo.nvd.cve.NvdCveResp;
import org.opensourceway.uvp.utility.EncryptUtil;
import org.opensourceway.uvp.utility.VulnSourceConfigUtil;
import org.opensourceway.uvp.utility.WebUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Optional;

/**
 * Client for retrieving data from NVD.
 * <p><a href="https://nvd.nist.gov/developers/vulnerabilities">NVD Vuln API DOC</a></p>
 * <p><a href="https://nvd.nist.gov/developers/products">NVD CPE API DOC</a></p>
 */
@Component
public class NvdImpl implements Nvd {

    @Value("${nvd.api.url}")
    private String baseUrl;

    @Value("${nvd.api.cves.page_size}")
    private Integer nvdCvesPageSize;

    @Value("${nvd.api.cpematch.page_size}")
    private Integer nvdCpeMatchPageSize;

    @Autowired
    private WebUtil webUtil;

    @Autowired
    private EncryptUtil encryptUtil;

    @Autowired
    private VulnSourceConfigUtil vulnSourceConfigUtil;

    @Override
    public NvdCveResp dumpCves(Integer startIndex) {
        var token = Optional.ofNullable(vulnSourceConfigUtil.getToken(VulnSource.NVD))
                .map(it -> encryptUtil.decrypt(it))
                .orElse(null);
        return webUtil.createWebClient(baseUrl)
                .get()
                .uri(uriBuilder -> uriBuilder
                        .path("/rest/json/cves/2.0")
                        .queryParam("startIndex", startIndex)
                        .queryParam("resultsPerPage", nvdCvesPageSize)
                        .queryParam("noRejected")
                        .build())
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("apiKey", token);
                    }
                })
                .retrieve()
                .bodyToMono(NvdCveResp.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)))
                .block(Duration.ofSeconds(120));
    }

    @Override
    public NvdCpeMatchResp dumpCpes(Integer startIndex) {
        var token = Optional.ofNullable(vulnSourceConfigUtil.getToken(VulnSource.NVD))
                .map(it -> encryptUtil.decrypt(it))
                .orElse(null);
        return webUtil.createWebClient(baseUrl)
                .get()
                .uri(uriBuilder -> uriBuilder
                        .path("/rest/json/cpematch/2.0")
                        .queryParam("startIndex", startIndex)
                        .queryParam("resultsPerPage", nvdCpeMatchPageSize)
                        .build())
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("apiKey", token);
                    }
                })
                .retrieve()
                .bodyToMono(NvdCpeMatchResp.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)))
                .block(Duration.ofSeconds(120));
    }
}
