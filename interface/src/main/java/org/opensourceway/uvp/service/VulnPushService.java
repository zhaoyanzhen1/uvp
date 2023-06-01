package org.opensourceway.uvp.service;

import org.opensourceway.uvp.entity.VulnPushTask;

/**
 * Service for pushing vulnerabilities to subscribers.
 */
public interface VulnPushService {
    /**
     * Find newly upsert pushable vulnerabilities and create push task tuples in table {@link VulnPushTask}.
     */
    void recordVulnForPush();

    /**
     * Push newly upsert pushable vulnerabilities to subscribers.
     */
    void pushVuln();
}
