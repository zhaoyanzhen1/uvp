package org.opensourceway.uvp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import org.opensourceway.uvp.enums.QuartzJobEnum;

/**
 * Configurations of quartz cron jobs.
 */
@Entity
public class QuartzJobConfig {
    /**
     * The name of a quartz job.
     */
    @Id
    @Enumerated(EnumType.STRING)
    @Convert(converter = QuartzJobEnum.QuartzJobConverter.class)
    @Column(columnDefinition = "TEXT", nullable = false)
    private QuartzJobEnum job;

    /**
     * Cron-expression of a quartz job.
     */
    @Column(columnDefinition = "TEXT")
    private String cron;

    public QuartzJobEnum getJob() {
        return job;
    }

    public void setJob(QuartzJobEnum job) {
        this.job = job;
    }

    public String getCron() {
        return cron;
    }

    public void setCron(String cron) {
        this.cron = cron;
    }
}
