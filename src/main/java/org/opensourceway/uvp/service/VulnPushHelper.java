package org.opensourceway.uvp.service;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.opensourceway.uvp.dao.VulnPushTaskRepository;
import org.opensourceway.uvp.entity.VulnPushTask;
import org.opensourceway.uvp.pojo.request.VulnPushRequest;
import org.opensourceway.uvp.utility.OsvEntityHelper;
import org.opensourceway.uvp.utility.WebUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Component
public class VulnPushHelper {
    private static final Logger logger = LoggerFactory.getLogger(VulnPushHelper.class);

    private static final Duration PUSH_TIMEOUT = Duration.ofSeconds(1);

    @Autowired
    private VulnPushTaskRepository vulnPushTaskRepository;

    @Autowired
    private WebUtil webUtil;

    @Autowired
    private OsvEntityHelper osvEntityHelper;

    @Transactional
    public void pushVulnAndUpdatePushStatus(UUID taskId) {
        var taskOptional = vulnPushTaskRepository.findById(taskId);
        if (taskOptional.isEmpty()) {
            return;
        }

        var task = taskOptional.get();
        var now = Timestamp.from(Instant.now());
        try {
            pushVuln(task);
            task.setSuccessfullyPushed(now);
        } catch (Exception e) {
            logger.warn("Failed to push vuln <{}> from source <{}> to subscriber <{}> with endpoint <{}>",
                    task.getVulnerability().getVulnId(), task.getVulnerability().getSource(),
                    task.getSubscriber().getName(), task.getSubscriber().getEndpoint());
            task.setErrorMessage(ExceptionUtils.getStackTrace(e));
        }
        task.setLastPushed(now);
        task.setPushCount(Optional.ofNullable(task.getPushCount()).orElse(0) + 1);
        vulnPushTaskRepository.save(task);
    }

    private void pushVuln(VulnPushTask task) {
        var endpoint = task.getSubscriber().getEndpoint();
        var request = new VulnPushRequest(task.getVulnerability().getSource().unifyPushSource(),
                osvEntityHelper.toVo(task.getVulnerability()));

        webUtil.createWebClient(endpoint)
                .post()
                .body(BodyInserters.fromValue(request))
                .retrieve()
                .onStatus(HttpStatusCode::isError, ClientResponse::createError)
                .bodyToMono(Void.class)
                .block(PUSH_TIMEOUT);
    }
}
