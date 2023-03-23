package org.opensourceway.uvp.utility;

import org.opensourceway.uvp.dao.QuartzJobConfigRepository;
import org.opensourceway.uvp.entity.QuartzJobConfig;
import org.opensourceway.uvp.enums.QuartzJobEnum;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class QuartzJobConfigUtil {

    @Autowired
    private QuartzJobConfigRepository repository;

    public String getJobCron(QuartzJobEnum job) {
        return repository.findByJob(job).map(QuartzJobConfig::getCron).orElse(job.getDefaultCron());
    }
}
