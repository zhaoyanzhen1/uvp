package org.opensourceway.uvp.service;

import org.opensourceway.uvp.dao.VulnerabilityRepository;
import org.opensourceway.uvp.entity.AffectedEvent;
import org.opensourceway.uvp.entity.AffectedPackage;
import org.opensourceway.uvp.entity.AffectedRange;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.Ecosystem;
import org.opensourceway.uvp.enums.EventType;
import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.helper.ecosystem.EcosystemHelper;
import org.opensourceway.uvp.helper.ecosystem.EcosystemHelperSelector;
import org.opensourceway.uvp.utility.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Transactional(rollbackFor = Exception.class)
public class VulnLocalServiceImpl implements VulnLocalService {

    private static final Logger logger = LoggerFactory.getLogger(VulnLocalServiceImpl.class);

    @Autowired
    private EcosystemHelperSelector ecosystemHelperSelector;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Override
    public List<Vulnerability> query(String purl) {
        logger.info("Try to query vulns from local databases for <{}>.", purl);
        var result = queryBySourceAndPurl(VulnSource.AGGREGATED, purl, true, null, null)
                .stream()
                .toList();
        logger.info("End to query vulns from local databases, get <{}> vulns affecting <{}>.", result.size(), purl);
        return result;
    }

    private List<Vulnerability> queryBySourceAndPurl(VulnSource source, String purl, Boolean accurate,
                                                     Integer limit, Integer offset) {
        var helper = ecosystemHelperSelector.getHelper(Ecosystem.findByPurlType(PurlUtil.newPurl(purl).getType()));
        var version = PurlUtil.newPurl(purl).getVersion();

        return vulnerabilityRepository.searchBySourceAndPurl(source, helper.normalizePurl(purl), accurate, limit, offset)
                .stream()
                .filter(vuln -> vuln.getAffectedPackages()
                        .stream()
                        .anyMatch(affectedPackage -> isAffected(helper, version, affectedPackage)))
                .toList();
    }

    private boolean isAffected(EcosystemHelper helper, String version, AffectedPackage affectedPackage) {
        if (helper.isAffectedVersion(version, affectedPackage.getVersions())) {
            return true;
        }

        for (AffectedRange affectedRange : affectedPackage.getRanges()) {
            if (helper.isAffectedVersion(
                    version,
                    getValueByEventType(affectedRange, EventType.INTRODUCED),
                    getValueByEventType(affectedRange, EventType.FIXED),
                    getValueByEventType(affectedRange, EventType.LAST_AFFECTED),
                    getValueByEventType(affectedRange, EventType.LIMIT))) {
                return true;
            }
        }

        return false;
    }

    private String getValueByEventType(AffectedRange affectedRange, EventType eventType) {
        return affectedRange.getEvents().stream()
                .filter(affectedEvent -> eventType.equals(affectedEvent.getType()))
                .map(AffectedEvent::getValue)
                .findFirst()
                .orElse(null);
    }

    @Override
    public Map<String, List<Vulnerability>> queryBatch(List<String> purls) {
        logger.info("Try to batch query vulns from local databases for <{}>.", purls);

        var result = purls.stream().collect(Collectors.toMap(Function.identity(), this::query));

        logger.info("End to batch query vulns from local databases for <{}>, get <{}> vulns.",
                purls, result.values().stream().mapToLong(List::size).sum());
        return result;
    }

    @Override
    public List<Vulnerability> search(String keyword, Integer limit, Integer offset) {
        logger.info("Try to search vulns for <{}>, limit: <{}>, offset: <{}>.", keyword, limit, offset);

        List<Vulnerability> vulns;
        var isValidPurl = PurlUtil.isValidPurl(keyword);

        if (isValidPurl) {
            logger.info("Try to search vulns for purl <{}>, limit: <{}>, offset: <{}>.", keyword, limit, offset);
            vulns = queryBySourceAndPurl(VulnSource.AGGREGATED, keyword, false, limit, offset);
        } else {
            logger.info("Try to search vulns for keyword <{}>, limit: <{}>, offset: <{}>.", keyword, limit, offset);
            vulns = vulnerabilityRepository.searchBySourceAndKeyword(VulnSource.AGGREGATED, keyword, limit, offset);
        }

        logger.info("End to search vulns for request <{}>, limit: <{}>, offset: <{}>, get <{}> vulns.",
                keyword, limit, offset, vulns.size());
        return vulns;
    }

    @Override
    public Vulnerability queryVulnDetail(String vulnId) {
        logger.info("Query details for vulnerability: <{}>", vulnId);
        return vulnerabilityRepository.findBySourceAndVulnIds(VulnSource.AGGREGATED, vulnId);
    }
}
