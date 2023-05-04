package org.opensourceway.uvp.batch.chunk.processor.aggregator;

import org.opensourceway.uvp.dao.VulnerabilityRepository;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.helper.aggragator.VulnAggregator;
import org.opensourceway.uvp.utility.OsvEntityHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class VulnAggregateProcessor implements ItemProcessor<List<String>, List<Vulnerability>> {

    private static final Logger logger = LoggerFactory.getLogger(VulnAggregateProcessor.class);

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnAggregator vulnAggregator;

    @Autowired
    private OsvEntityHelper osvEntityHelper;

    private final boolean publicOnly;

    public VulnAggregateProcessor(boolean publicOnly) {
        this.publicOnly = publicOnly;
    }

    @Override
    public List<Vulnerability> process(List<String> vulnIds) {
        logger.info("Start to aggregate <{}> vulns, public-only: {}.", vulnIds.size(), publicOnly);

        var sources = (publicOnly ? VulnSource.getPublicSource() : VulnSource.getPublicAndPrivateSource())
                .stream().map(Enum::name).toList();
        var vulns = vulnerabilityRepository.findBySourcesAndVulnIds(sources, vulnIds);
        var aggregatedVulns = vulnAggregator.aggregate(vulns, vulnIds)
                .stream()
                .map(vuln -> osvEntityHelper.copyEntity(vuln,
                        publicOnly ? VulnSource.AGGREGATED : VulnSource.AGGREGATED_WITH_PRIVATE))
                .distinct()
                .toList();

        logger.info("End to aggregate <{}> vulns, public-only: {}, get <{}> vulns.",
                vulnIds.size(), publicOnly, aggregatedVulns.size());
        return aggregatedVulns;
    }
}
