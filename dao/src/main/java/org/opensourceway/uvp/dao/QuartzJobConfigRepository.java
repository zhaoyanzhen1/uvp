package org.opensourceway.uvp.dao;

import org.opensourceway.uvp.entity.QuartzJobConfig;
import org.opensourceway.uvp.enums.QuartzJobEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface QuartzJobConfigRepository extends JpaRepository<QuartzJobConfig, String> {

    @Query(value = "SELECT * FROM quartz_job_config WHERE job = :#{#job?.name()}", nativeQuery = true)
    Optional<QuartzJobConfig> findByJob(QuartzJobEnum job);
}
