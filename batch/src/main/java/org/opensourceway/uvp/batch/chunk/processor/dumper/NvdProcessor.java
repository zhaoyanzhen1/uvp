package org.opensourceway.uvp.batch.chunk.processor.dumper;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.clients.Nvd;
import org.opensourceway.uvp.dao.CpeMatchRepository;
import org.opensourceway.uvp.dao.CpePurlRepository;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.EventType;
import org.opensourceway.uvp.enums.OsvSchemaVersion;
import org.opensourceway.uvp.enums.ReferenceType;
import org.opensourceway.uvp.enums.ScoringSystem;
import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.pojo.nvd.cve.Configuration;
import org.opensourceway.uvp.pojo.nvd.cve.Cpe;
import org.opensourceway.uvp.pojo.nvd.cve.Description;
import org.opensourceway.uvp.pojo.nvd.cve.Metrics;
import org.opensourceway.uvp.pojo.nvd.cve.Node;
import org.opensourceway.uvp.pojo.nvd.cve.NvdCve;
import org.opensourceway.uvp.pojo.nvd.cve.NvdCveWrapper;
import org.opensourceway.uvp.pojo.nvd.cve.Reference;
import org.opensourceway.uvp.pojo.osv.OsvAffected;
import org.opensourceway.uvp.pojo.osv.OsvEvent;
import org.opensourceway.uvp.pojo.osv.OsvRange;
import org.opensourceway.uvp.pojo.osv.OsvReference;
import org.opensourceway.uvp.pojo.osv.OsvSeverity;
import org.opensourceway.uvp.pojo.osv.OsvVulnerability;
import org.opensourceway.uvp.utility.OsvEntityHelper;
import org.opensourceway.uvp.utility.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ObjectUtils;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.values.LogicalValue;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class NvdProcessor implements ItemProcessor<Integer, List<Vulnerability>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(NvdProcessor.class);

    private Map<String, List<String>> cpePurlMapping = new HashMap<>();

    private Map<String, List<String>> matchCriteriaIdToCpes = new HashMap<>();

    @Autowired
    private Nvd nvd;

    @Autowired
    private CpePurlRepository cpePurlRepository;

    @Autowired
    private CpeMatchRepository cpeMatchRepository;

    @Autowired
    private OsvEntityHelper osvEntityHelper;

    @Override
    public List<Vulnerability> process(@NotNull Integer startIndex) {
        logger.info("Start to get NVD CVE with startIndex: <{}>.", startIndex);

        if (startIndex == Integer.MIN_VALUE) {
            return null;
        }

        var resp = nvd.dumpCves(startIndex);
        // Maybe some failure occur, try to call NVD API next time.
        if (Objects.isNull(resp)) {
            logger.warn("Get null response from NVD.");
            throw new RuntimeException("Get null response from NVD.");
        }

        try {
            var vulns = resp.getVulnerabilities()
                    .stream()
                    .map(NvdCveWrapper::cve)
                    .map(this::toOsv)
                    .map(it -> osvEntityHelper.toVuln(VulnSource.NVD, it))
                    .distinct()
                    .toList();

            logger.info("End to process NVD CVE.");
            return vulns;
        } catch (Exception e) {
            logger.warn("Exception occurs when process NVD CVE.", e);
            throw new RuntimeException(e);
        }
    }

    private OsvVulnerability toOsv(NvdCve cve) {
        var osv = new OsvVulnerability();
        osv.setSchemaVersion(OsvSchemaVersion.V1_3_0);
        osv.setId(cve.getId());
        osv.setModified(convertNvdTimestamp(cve.getLastModified()));
        osv.setPublished(convertNvdTimestamp(cve.getPublished()));
        osv.setWithdrawn(null);
        osv.setAliases(null);
        osv.setRelated(null);
        osv.setSummary(null);
        osv.setDetails(cve.getDescriptions().stream()
                .filter(it -> StringUtils.equals(it.lang(), Description.Lang.EN.getLang())).map(Description::value)
                .findFirst().orElse(null));
        osv.setSeverity(toOsv(cve.getMetrics()));
        osv.setAffected(toOsv(cve.getConfigurations()));
        osv.setReferences(cve.getReferences().stream().map(this::toOsv).distinct().toList());
        osv.setCredits(null);
        return osv;
    }

    private List<OsvAffected> toOsv(List<Configuration> configurations) {
        if (ObjectUtils.isEmpty(configurations)) {
            return null;
        }

        return configurations.stream()
                .map(Configuration::nodes)
                .filter(nodes -> !ObjectUtils.isEmpty(nodes))
                .flatMap(List::stream)
                .map(Node::cpeMatch)
                .filter(cpes -> !ObjectUtils.isEmpty(cpes))
                .flatMap(List::stream)
                .map(this::toOsv)
                .filter(Objects::nonNull)
                .flatMap(List::stream)
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(OsvAffected::getPkg, Collectors.toList()))
                .values()
                .stream()
                .map(this::mergeAffected)
                .flatMap(List::stream)
                .toList();
    }

    private List<OsvAffected> toOsv(Cpe cpe) {
        if (!cpe.vulnerable()) {
            return null;
        }

        var cpeNames = new ArrayList<>(matchCriteriaIdToCpes.getOrDefault(cpe.matchCriteriaId(), new ArrayList<>()));
        cpeNames.add(cpe.criteria());

        var purls = cpeNames.stream()
                .map(it -> cpePurlMapping.get(it))
                .filter(Objects::nonNull)
                .flatMap(List::stream)
                .distinct()
                .toList();

        if (ObjectUtils.isEmpty(purls)) {
            return null;
        }

        return purls.stream().map(purl -> toOsv(cpe, purl, cpeNames)).toList();
    }

    private OsvAffected toOsv(Cpe cpe, String purl, List<String> cpeNames) {
        try {
            var osvAffected = new OsvAffected();

            osvAffected.setPkg(PurlUtil.purlToOsvPackage(purl));
            osvAffected.setRanges(List.of(toOsvRange(cpe, purl)));
            osvAffected.setVersions(getVersionsFromCpe(cpeNames));

            return osvAffected;
        } catch (Exception e) {
            return null;
        }
    }

    private List<String> getVersionsFromCpe(List<String> cpeNames) {
        // TODO Expand versions from Starting and Ending
        return cpeNames.stream().map(this::getVersionFromCpe).filter(Objects::nonNull).distinct().toList();
    }

    private String getVersionFromCpe(String cpe) {
        try {
            var cpeObj = CpeParser.parse(cpe);
            if (Arrays.stream(LogicalValue.values()).map(LogicalValue::getAbbreviation).toList()
                    .contains(cpeObj.getVersion())) {
                return null;
            }
            if (Arrays.stream(LogicalValue.values()).map(LogicalValue::getAbbreviation).toList()
                    .contains(cpeObj.getUpdate())) {
                return cpeObj.getVersion();
            }
            return "%s-%s".formatted(cpeObj.getVersion(), cpeObj.getUpdate());
        } catch (CpeParsingException e) {
            // The exception should not be thrown.
            logger.warn("Invalid CPE: <{}>", cpe);
            return null;
        }
    }

    private OsvRange toOsvRange(Cpe cpe, String purl) {
        var osvRange = new OsvRange();
        osvRange.setType(PurlUtil.purlToOsvPackage(purl).getEcosystem().getVersionType());

        List<OsvEvent> osvEvents = new ArrayList<>();
        if (StringUtils.isNotBlank(cpe.versionStartIncluding())) {
            var osvEvent = new OsvEvent();
            osvEvent.put(EventType.INTRODUCED, cpe.versionStartIncluding());
            osvEvents.add(osvEvent);
        }
        if (StringUtils.isNotBlank(cpe.versionStartExcluding())) {
            // TODO Find the next version
        }
        if (StringUtils.isNotBlank(cpe.versionEndIncluding())) {
            var osvEvent = new OsvEvent();
            osvEvent.put(EventType.LAST_AFFECTED, cpe.versionEndIncluding());
            osvEvents.add(osvEvent);
        }
        if (StringUtils.isNotBlank(cpe.versionEndExcluding())) {
            var osvEvent = new OsvEvent();
            osvEvent.put(EventType.FIXED, cpe.versionEndExcluding());
            osvEvents.add(osvEvent);
        }
        osvRange.setEvents(osvEvents);

        return osvRange;
    }

    /**
     * Merge versions of the same affected packages.
     * Leave affected packages with range events alone.
     *
     * @param osvAffectedList Unmerged list of OsvAffected
     * @return A list of merged OsvAffected.
     */
    private List<OsvAffected> mergeAffected(List<OsvAffected> osvAffectedList) {
        var result = new ArrayList<OsvAffected>();
        var versionMerged = new ArrayList<String>();

        osvAffectedList.forEach(osvAffected -> {
            if (osvAffected.getRanges().stream().map(OsvRange::getEvents)
                    .anyMatch(events -> !ObjectUtils.isEmpty(events))) {
                result.add(osvAffected);
            } else {
                versionMerged.addAll(osvAffected.getVersions());
            }
        });

        if (!ObjectUtils.isEmpty(versionMerged)) {
            var osvAffectedMerged = new OsvAffected();
            osvAffectedMerged.setPkg(osvAffectedList.get(0).getPkg());
            osvAffectedMerged.setRanges(List.of());
            osvAffectedMerged.setVersions(versionMerged);
            result.add(osvAffectedMerged);
        }

        return result;
    }

    private List<OsvSeverity> toOsv(Metrics metrics) {
        List<OsvSeverity> severities = new ArrayList<>();
        if (!ObjectUtils.isEmpty(metrics.cvssMetricV2())) {
            var severity = new OsvSeverity();
            severity.setType(ScoringSystem.CVSS_V2);
            severity.setScore(metrics.cvssMetricV2().get(0).cvssData().vectorString());
            severities.add(severity);
        }
        if (!ObjectUtils.isEmpty(metrics.cvssMetricV30())) {
            var severity = new OsvSeverity();
            severity.setType(ScoringSystem.CVSS_V3);
            severity.setScore(metrics.cvssMetricV30().get(0).cvssData().vectorString());
            severities.add(severity);
        }
        if (!ObjectUtils.isEmpty(metrics.cvssMetricV31())) {
            var severity = new OsvSeverity();
            severity.setType(ScoringSystem.CVSS_V3);
            severity.setScore(metrics.cvssMetricV31().get(0).cvssData().vectorString());
            severities.add(severity);
        }
        return severities;
    }

    private OsvReference toOsv(Reference reference) {
        var osvReference = new OsvReference();
        osvReference.setType(ObjectUtils.isEmpty(reference.tags()) ? ReferenceType.WEB :
                reference.tags().get(0).getOsvReferenceType());
        osvReference.setUrl(reference.url());
        return osvReference;
    }

    /**
     * Parse NVD timestamp to ISO-8601 timestamp.
     * <p>1970-01-01T00:00:00 -> 1970-01-01T00:00:00Z</p>
     *
     * @param timestamp NVD timestamp
     * @return ISO-8601 timestamp
     */
    private String convertNvdTimestamp(String timestamp) {
        try {
            return new SimpleDateFormat("yyyy-MM-dd'T'hh:mm:ss.SSS").parse(timestamp).toInstant().toString();
        } catch (ParseException e) {
            // If failed to parse the timestamp, return 1970-01-01T00:00:00Z as an alternative.
            return Instant.EPOCH.toString();
        }
    }

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        logger.info("Fetch CPE-PURL mapping and CPE matches from database.");
        cpePurlRepository.findAll().forEach(it -> it.getCpes().forEach(cpe -> cpePurlMapping.put(cpe, it.getPurls())));
        cpeMatchRepository.findAll().forEach(it -> matchCriteriaIdToCpes.put(it.getMatchCriteriaId(), it.getCpes()));
    }

    @Override
    public ExitStatus afterStep(@NotNull StepExecution stepExecution) {
        cpePurlMapping.clear();
        matchCriteriaIdToCpes.clear();
        return null;
    }
}
