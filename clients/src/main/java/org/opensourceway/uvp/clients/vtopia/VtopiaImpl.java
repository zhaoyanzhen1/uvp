package org.opensourceway.uvp.clients.vtopia;

import org.opensourceway.uvp.clients.Vtopia;
import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.pojo.vtopia.VtopiaResp;
import org.opensourceway.uvp.utility.EncryptUtil;
import org.opensourceway.uvp.utility.VulnSourceConfigUtil;
import org.opensourceway.uvp.utility.WebUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Optional;

/**
 * Client for retrieving data from Vtopia.
 */
@Component
public class VtopiaImpl implements Vtopia {

    @Autowired
    private WebUtil webUtil;

    @Autowired
    private EncryptUtil encryptUtil;

    @Autowired
    private VulnSourceConfigUtil vulnSourceConfigUtil;

    @Override
    public VtopiaResp dumpCves(Integer page, Integer pageSize) {
        var endpoint = Optional.ofNullable(vulnSourceConfigUtil.getEndpoint(VulnSource.VTOPIA))
                .map(it -> encryptUtil.decrypt(it))
                .orElseThrow(() -> new RuntimeException("Check the endpoint of <%s>".formatted(VulnSource.VTOPIA)));

        return webUtil.createWebClient(endpoint)
                .get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam("page_num", page)
                        .queryParam("count_per_page", pageSize)
                        .build())
                .retrieve()
                .bodyToMono(VtopiaResp.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)))
                .block(Duration.ofSeconds(120));
    }
}
