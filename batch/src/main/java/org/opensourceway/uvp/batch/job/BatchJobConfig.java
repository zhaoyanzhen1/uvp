package org.opensourceway.uvp.batch.job;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.explore.JobExplorer;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration
public class BatchJobConfig {

    private static final Logger logger = LoggerFactory.getLogger(BatchJobConfig.class);

    @Autowired
    private JobLauncher jobLauncher;

    @Autowired
    private JobExplorer jobExplorer;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private Job dumpVulnJob;

    /**
     * {@link JobLauncher#run} is synchronized, thread will be blocked until the job finishes or fails.
     */
    public void launchDumpJob() throws Exception {
        if (jobExplorer.findRunningJobExecutions(dumpVulnJob.getName()).size() != 0) {
            logger.warn("Another dump job is running");
            return;
        }

        jobLauncher.run(dumpVulnJob, new JobParametersBuilder()
                .addLong("startTimestamp", System.currentTimeMillis())
                .toJobParameters());
    }
}