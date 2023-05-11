package org.opensourceway.uvp.batch.job;

import org.opensourceway.uvp.batch.BatchConstant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.configuration.DuplicateJobException;
import org.springframework.batch.core.configuration.JobFactory;
import org.springframework.batch.core.configuration.JobRegistry;
import org.springframework.batch.core.configuration.support.ReferenceJobFactory;
import org.springframework.batch.core.explore.JobExplorer;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.core.launch.JobOperator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Configuration
public class BatchJobConfig {

    private static final Logger logger = LoggerFactory.getLogger(BatchJobConfig.class);

    @Autowired
    private JobLauncher jobLauncher;

    @Autowired
    private JobExplorer jobExplorer;

    @Autowired
    private JobOperator jobOperator;

    @Autowired
    private JobRegistry jobRegistry;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private Job dumpVulnJob;

    /**
     * {@link JobLauncher#run} is synchronized, thread will be blocked until the job finishes or fails.
     */
    public void launchDumpJob() throws Exception {
        stopTimeoutDumpJob();

        if (jobExplorer.findRunningJobExecutions(dumpVulnJob.getName()).size() != 0) {
            logger.warn("Another dump job is running");
            return;
        }

        jobLauncher.run(dumpVulnJob, new JobParametersBuilder()
                .addLong("startTimestamp", System.currentTimeMillis())
                .toJobParameters());
    }

    private void stopTimeoutDumpJob() {
        jobExplorer.findRunningJobExecutions(dumpVulnJob.getName())
                .parallelStream()
                .filter(it -> Objects.isNull(it.getStartTime()) ||
                        ChronoUnit.SECONDS.between(it.getStartTime(), LocalDateTime.now()) >= BatchConstant.DUMP_JOB_TIMEOUT)
                .map(JobExecution::getId)
                .forEach(this::stopRunningJob);
    }

    private void stopRunningJob(long jobExecutionId) {
        if (!jobOperator.getJobNames().contains(dumpVulnJob.getName())) {
            JobFactory jobFactory = new ReferenceJobFactory(dumpVulnJob);
            try {
                jobRegistry.register(jobFactory);
            } catch (DuplicateJobException ignored) {

            }
        }

        try {
            jobOperator.stop(jobExecutionId);
            logger.warn("Stop timeout job with job_execution_id: <{}>", jobExecutionId);
        } catch (Exception e) {
            logger.warn("Failed to stop timeout job with job_execution_id: <{}>", jobExecutionId, e);
        }

        var jobExecution = jobExplorer.getJobExecution(jobExecutionId);
        var now = LocalDateTime.now();
        while (Objects.nonNull(jobExecution) && jobExecution.isRunning() &&
                ChronoUnit.SECONDS.between(now, LocalDateTime.now()) <= BatchConstant.STOP_DUMP_JOB_TIMEOUT) {
            jobExecution = jobExplorer.getJobExecution(jobExecutionId);
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ignored) {

            }
        }

        if (Objects.nonNull(jobExecution) && jobExecution.isStopping()) {
            try {
                jobOperator.abandon(jobExecutionId);
                logger.warn("Abandon timeout job with job_execution_id: <{}>", jobExecutionId);
            } catch (Exception e) {
                logger.warn("Failed to abandon timeout job with job_execution_id: <{}>", jobExecutionId, e);
            }
        }
    }
}