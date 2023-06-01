package org.opensourceway.uvp.dao;

import org.opensourceway.uvp.entity.VulnPushTask;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface VulnPushTaskRepository extends JpaRepository<VulnPushTask, UUID> {
    @Query(value = """
            SELECT *
            FROM vuln_push_task
            WHERE successfully_pushed IS NULL
                AND subscriber_id = :subscriberId
            ORDER BY created
            FOR UPDATE SKIP LOCKED
            LIMIT :limit
            """, nativeQuery = true)
    List<VulnPushTask> findPendingPushTaskBySubscriberWithLockWithLimit(UUID subscriberId, Integer limit);
}