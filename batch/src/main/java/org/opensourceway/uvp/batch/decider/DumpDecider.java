package org.opensourceway.uvp.batch.decider;


import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.utility.VulnSourceConfigUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.job.flow.FlowExecutionStatus;
import org.springframework.batch.core.job.flow.JobExecutionDecider;
import org.springframework.beans.factory.annotation.Autowired;

public class DumpDecider implements JobExecutionDecider {

    private final static Logger logger = LoggerFactory.getLogger(DumpDecider.class);

    private final VulnSource vulnSource;

    public DumpDecider(VulnSource vulnSource) {
        this.vulnSource = vulnSource;
    }

    @Autowired
    private VulnSourceConfigUtil vulnSourceConfigUtil;

    @NotNull
    @Override
    public FlowExecutionStatus decide(@NotNull JobExecution jobExecution, StepExecution stepExecution) {
        if (!vulnSourceConfigUtil.importEnabled(vulnSource)) {
            logger.info("DumpVuln for <{}> is disabled!", vulnSource);
            return new FlowExecutionStatus("no-op");
        }

        logger.info("DumpVuln for <{}> is enabled.", vulnSource);
        return FlowExecutionStatus.COMPLETED;
    }
}
