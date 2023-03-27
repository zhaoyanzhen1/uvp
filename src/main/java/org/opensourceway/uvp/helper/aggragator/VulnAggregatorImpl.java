package org.opensourceway.uvp.helper.aggragator;

import org.opensourceway.uvp.entity.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
public class VulnAggregatorImpl implements VulnAggregator {

    private static final Logger logger = LoggerFactory.getLogger(VulnAggregatorImpl.class);

    @Override
    public List<Vulnerability> aggregate(List<Vulnerability> vulns) {
        logger.info("Aggregate <{}> vulns", vulns.size());

        // Map vuln id and aliases.
        Map<String, Vulnerability> vulnIdToVuln = new HashMap<>();
        vulns.forEach(vuln -> {
            vulnIdToVuln.merge(vuln.getVulnId(), vuln, (oldValue, value) ->
                    value.getSource().hasHigherPriority(oldValue.getSource()) ? value : oldValue);

            Optional.ofNullable(vuln.getAliases())
                    .ifPresent(aliases -> aliases.forEach(alias -> vulnIdToVuln.merge(
                            alias.getAlias(), vuln, (oldValue, value) ->
                            value.getSource().hasHigherPriority(oldValue.getSource()) ? value : oldValue)));
        });
        var result = vulnIdToVuln.values().stream().toList();

        logger.info("Get <{}> vulns after aggregating", result.size());
        return result;
    }
}
