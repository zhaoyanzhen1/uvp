package org.opensourceway.uvp.batch.step;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.dao.VulnerabilityRepository;
import org.opensourceway.uvp.enums.VulnSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;

public class UpdateStateOfUnpushableVulnsStep implements Tasklet {

    private static final Logger logger = LoggerFactory.getLogger(UpdateStateOfUnpushableVulnsStep.class);

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) {
        logger.info("Start to update state of unpushable vulnerabilities");

        var vulns = vulnerabilityRepository.findUpsertUnpushableVulns(
                VulnSource.getUnpushableSources().stream().map(Enum::name).toList());
        vulns.forEach(vuln -> {
            vuln.setUpdated(false);
            vuln.setInserted(false);
        });
        vulnerabilityRepository.saveAll(vulns);

        logger.info("End to update state of unpushable vulnerabilities");
        return RepeatStatus.FINISHED;
    }
}
