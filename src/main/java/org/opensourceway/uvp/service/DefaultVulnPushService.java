package org.opensourceway.uvp.service;

import org.opensourceway.uvp.dao.SubscriberRepository;
import org.opensourceway.uvp.dao.VulnPushTaskRepository;
import org.opensourceway.uvp.dao.VulnerabilityRepository;
import org.opensourceway.uvp.entity.Subscriber;
import org.opensourceway.uvp.entity.VulnPushTask;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.PushType;
import org.opensourceway.uvp.enums.VulnSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service
@Transactional(rollbackFor = Exception.class)
public class DefaultVulnPushService implements VulnPushService {
    private static final Logger logger = LoggerFactory.getLogger(DefaultVulnPushService.class);

    private static final int RECORD_BATCH_SIZE = 1000;

    private static final int PUSH_BATCH_SIZE = 1000;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnPushTaskRepository vulnPushTaskRepository;

    @Autowired
    private SubscriberRepository subscriberRepository;

    @Autowired
    private VulnPushHelper vulnPushHelper;

    @Override
    public void recordVulnForPush() {
        logger.info("Start to record vuln for push.");

        var activeSubscribers = subscriberRepository.findByActive(true);
        if (ObjectUtils.isEmpty(activeSubscribers)) {
            logger.info("No active subscriber.");
            return;
        }

        var vulns = vulnerabilityRepository.findRecentUpsertPushableVulnsWithLockWithLimit(
                VulnSource.getPushableSources().stream().map(Enum::name).toList(), RECORD_BATCH_SIZE);
        List<VulnPushTask> vulnPushTasks = new ArrayList<>();

        vulns.forEach(vuln -> {
            activeSubscribers.forEach(subscriber -> {
                if (!shouldVulnPushToSubscriber(vuln, subscriber)) {
                    return;
                }
                var vulnPushStatus = new VulnPushTask();
                vulnPushStatus.setType(Objects.equals(Boolean.TRUE, vuln.getInserted()) ? PushType.INSERT : PushType.UPDATE);
                vulnPushStatus.setSubscriber(subscriber);
                vulnPushStatus.setVulnerability(vuln);
                vulnPushTasks.add(vulnPushStatus);
            });
            vuln.setInserted(false);
            vuln.setUpdated(false);
        });

        vulnerabilityRepository.saveAll(vulns);
        if (!ObjectUtils.isEmpty(vulnPushTasks)) {
            vulnPushTaskRepository.saveAll(vulnPushTasks);
            logger.info("Insert <{}> push tasks.", vulnPushTasks.size());
        }

        logger.info("End to record vuln for push.");
    }

    private boolean shouldVulnPushToSubscriber(Vulnerability vuln, Subscriber subscriber) {
        if (Objects.equals(Boolean.TRUE, subscriber.getPrivateAvailable()) && vuln.getSource().isPrivatePushable()) {
            return true;
        }

        if (!Objects.equals(Boolean.TRUE, subscriber.getPrivateAvailable()) && vuln.getSource().isPublicPushable()) {
            return true;
        }

        return false;
    }

    @Override
    public void pushVuln() {
        logger.info("Start to push vuln.");
        subscriberRepository.findByActive(true)
                .parallelStream()
                .forEach(subscriber -> vulnPushTaskRepository
                        .findPendingPushTaskBySubscriberWithLockWithLimit(subscriber.getId(), PUSH_BATCH_SIZE)
                        .stream()
                        .map(VulnPushTask::getId)
                        .forEach(vulnPushHelper::pushVulnAndUpdatePushStatus));
        logger.info("End to push vuln.");
    }
}
