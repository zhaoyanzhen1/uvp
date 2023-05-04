package org.opensourceway.uvp.helper.aggragator;

import org.opensourceway.uvp.entity.Alias;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.OsvSchemaVersion;
import org.opensourceway.uvp.utility.OsvEntityHelper;
import org.opensourceway.uvp.utility.RegexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class VulnAggregatorImpl implements VulnAggregator {

    private static final Logger logger = LoggerFactory.getLogger(VulnAggregatorImpl.class);

    @Autowired
    private OsvEntityHelper osvEntityHelper;

    @Override
    public List<Vulnerability> aggregate(List<Vulnerability> vulns) {
        logger.info("Aggregate <{}> vulns", vulns.size());

        Map<String, Pair<Set<String>, List<Vulnerability>>> vulnIdToAliasAndVuln = new HashMap<>();
        vulns.forEach(vuln -> groupVulnsByVulnId(vuln, vulnIdToAliasAndVuln));
        var result = vulnIdToAliasAndVuln.entrySet().stream()
                .map(it -> aggregate(it.getKey(), it.getValue().getFirst().stream().toList(), it.getValue().getSecond()))
                .toList();

        logger.info("Get <{}> vulns after aggregating", result.size());
        return result;
    }

    private void groupVulnsByVulnId(Vulnerability vuln,
                                    Map<String, Pair<Set<String>, List<Vulnerability>>> vulnIdToAliasAndVuln) {
        if (!RegexUtil.isCveId(vuln.getVulnId())
                && vuln.getAliases().stream().map(Alias::getAlias).anyMatch(RegexUtil::isCveId)) {
            var nonCveAliases = Stream.concat(
                    vuln.getAliases().stream().map(Alias::getAlias).filter(it -> !RegexUtil.isCveId(it)),
                    Stream.of(vuln.getVulnId())).collect(Collectors.toSet());
            vuln.getAliases().stream().map(Alias::getAlias).filter(RegexUtil::isCveId)
                    .forEach(it -> groupAliasesAndVulns(vuln, it, nonCveAliases, vulnIdToAliasAndVuln));
        } else {
            groupAliasesAndVulns(vuln, vuln.getVulnId(),
                    vuln.getAliases().stream().map(Alias::getAlias).collect(Collectors.toSet()), vulnIdToAliasAndVuln);
        }
    }

    private void groupAliasesAndVulns(Vulnerability vuln, String vulnId, Set<String> aliases,
                                      Map<String, Pair<Set<String>, List<Vulnerability>>> vulnIdToAliasAndVuln) {
        if (vulnIdToAliasAndVuln.containsKey(vulnId)) {
            var pair = vulnIdToAliasAndVuln.get(vulnId);
            pair.getFirst().addAll(aliases);
            pair.getSecond().add(vuln);
        } else {
            vulnIdToAliasAndVuln.put(vulnId, Pair.of(aliases, new ArrayList<>(List.of(vuln))));
        }
    }

    private Vulnerability aggregate(String vulnId, List<String> aliases, List<Vulnerability> vulns) {
        var vuln = new Vulnerability();

        vuln.setSchemaVersion(OsvSchemaVersion.newestVersion());
        vuln.setVulnId(vulnId);
        vuln.setRelated(vulns.stream().map(Vulnerability::getRelated).filter(Objects::nonNull)
                .flatMap(List::stream).distinct().toList());
        vuln.setModified(vulns.stream().map(Vulnerability::getModified).filter(Objects::nonNull)
                .max(Comparator.naturalOrder()).orElse(null));
        vuln.setPublished(vulns.stream().map(Vulnerability::getPublished).filter(Objects::nonNull)
                .max(Comparator.naturalOrder()).orElse(null));
        vuln.setWithdrawn(vulns.stream().map(Vulnerability::getWithdrawn).filter(Objects::nonNull)
                .max(Comparator.naturalOrder()).orElse(null));
        vuln.setSummary(vulns.stream().map(Vulnerability::getSummary).filter(Objects::nonNull)
                .findFirst().orElse(null));
        vuln.setDetail(vulns.stream().map(Vulnerability::getDetail).filter(Objects::nonNull)
                .findFirst().orElse(null));
        vuln.setDatabaseSpecific(vulns.stream().filter(it -> !ObjectUtils.isEmpty(it.getDatabaseSpecific()))
                .collect(Collectors.toMap(it -> it.getSource().name(), Vulnerability::getDatabaseSpecific, (oldVal, newVal) -> newVal)));
        vuln.setSeverities(vulns.stream()
                .max(Comparator.comparing(Vulnerability::getModified, Comparator.nullsLast(Comparator.naturalOrder())))
                .map(Vulnerability::getSeverities).orElse(new ArrayList<>()));
        vuln.setReferences(vulns.stream().map(Vulnerability::getReferences).flatMap(List::stream).distinct().toList());
        vuln.setCredits(vulns.stream().map(Vulnerability::getCredits).flatMap(List::stream).distinct().toList());
        vuln.setAffectedPackages(vulns.stream().map(Vulnerability::getAffectedPackages).flatMap(List::stream).distinct().toList());
        vuln.setAliases(aliases.stream().map(it -> osvEntityHelper.toEntity(it, vuln)).toList());

        return vuln;
    }
}
