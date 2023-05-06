package org.opensourceway.uvp.batch.chunk.processor.dumper;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.clients.Vtopia;
import org.opensourceway.uvp.clients.provider.converter.VulnConverter;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.Ecosystem;
import org.opensourceway.uvp.enums.OsvSchemaVersion;
import org.opensourceway.uvp.enums.ReferenceType;
import org.opensourceway.uvp.enums.ScoringSystem;
import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.pojo.osv.OsvAffected;
import org.opensourceway.uvp.pojo.osv.OsvPackage;
import org.opensourceway.uvp.pojo.osv.OsvReference;
import org.opensourceway.uvp.pojo.osv.OsvSeverity;
import org.opensourceway.uvp.pojo.osv.OsvVulnerability;
import org.opensourceway.uvp.pojo.vtopia.Description;
import org.opensourceway.uvp.pojo.vtopia.Impact;
import org.opensourceway.uvp.pojo.vtopia.Reference;
import org.opensourceway.uvp.pojo.vtopia.VtopiaVulnerability;
import org.opensourceway.uvp.utility.OsvEntityHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.util.ObjectUtils;

import java.net.URI;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Collectors;

public class VtopiaProcessor implements ItemProcessor<Integer, List<Vulnerability>> {

    private static final Logger logger = LoggerFactory.getLogger(VtopiaProcessor.class);

    @Value("${vtopia.api.page_size}")
    private Integer pageSize;

    @Autowired
    private Vtopia vtopia;

    @Autowired
    private OsvEntityHelper osvEntityHelper;


    @Override
    public List<Vulnerability> process(@NotNull Integer page) {
        logger.info("Start to get Vtopia CVE with page: <{}>.", page);

        if (page == Integer.MIN_VALUE) {
            return null;
        }

        var resp = vtopia.dumpCves(page, pageSize);
        // Maybe some failure occur, try to call Vtopia API next time.
        if (Objects.isNull(resp)) {
            logger.warn("Get null response from Vtopia.");
            throw new RuntimeException("Get null response from Vtopia.");
        }

        try {
            var converter = new VtopiaConverter();
            var vulns = resp.body().list()
                    .stream()
                    .map(converter::convert)
                    .map(it -> osvEntityHelper.toVuln(VulnSource.VTOPIA, it))
                    .distinct()
                    .toList();

            logger.info("End to process Vtopia CVE.");
            return vulns;
        } catch (Exception e) {
            logger.warn("Exception occurs when process Vtopia CVE.", e);
            throw new RuntimeException(e);
        }
    }

    class VtopiaConverter implements VulnConverter<VtopiaVulnerability> {
        @Override
        public OsvVulnerability convert(VtopiaVulnerability vuln) {
            var osv = new OsvVulnerability();
            osv.setSchemaVersion(OsvSchemaVersion.newestVersion());
            osv.setId(vuln.getCveNum());
            osv.setModified(convertVtopiaTimestamp(vuln.getEndGetTime()));
            osv.setPublished(convertVtopiaTimestamp(vuln.getPublishedDate()));
            osv.setWithdrawn(null);
            osv.setAliases(null);
            osv.setRelated(null);
            osv.setSummary(null);
            osv.setDetails(Optional.ofNullable(vuln.getDescription()).map(Description::en).orElse(null));
            osv.setSeverity(toOsv(vuln.getImpact()));
            osv.setAffected(toOsv(vuln.getPackName()));
            osv.setReferences(Objects.isNull(vuln.getReferenceData()) ? null
                    : vuln.getReferenceData().stream().map(this::toOsv).filter(Objects::nonNull).distinct().toList());
            osv.setCredits(null);

            osv.setCredits(null);
            return osv;
        }

        private List<OsvAffected> toOsv(List<String> packNames) {
            if (ObjectUtils.isEmpty(packNames)) {
                return null;
            }

            return packNames.stream()
                    .map(this::parsePackName)
                    .filter(Objects::nonNull)
                    .collect(Collectors.groupingBy(Pair::getFirst, Collectors.mapping(Pair::getSecond, Collectors.toSet())))
                    .entrySet()
                    .stream()
                    .map(this::toOsv)
                    .toList();
        }

        /**
         * Convert 'kafka==2.8.2' to 'kafka' and '2.8.2'
         *
         * @param packName String of Vtopia-defined affected package and its version.
         * @return Pair of affected package and its version.
         */
        private Pair<String, String> parsePackName(String packName) {
            var split = packName.split("==", 2);
            if (split.length != 2) {
                return null;
            }
            return Pair.of(split[0].strip(), split[1].strip());
        }

        private OsvAffected toOsv(Map.Entry<String, Set<String>> affectedPackageWithVersions) {
            var osvAffected = new OsvAffected();

            osvAffected.setPkg(toOsvPackage(affectedPackageWithVersions.getKey()));
            osvAffected.setRanges(List.of());
            osvAffected.setVersions(affectedPackageWithVersions.getValue().stream().toList());

            return osvAffected;
        }

        private OsvPackage toOsvPackage(String packageName) {
            var osvPackage = new OsvPackage();
            osvPackage.setPurl(null);
            osvPackage.setName(packageName);
            osvPackage.setEcosystem(Ecosystem.UNKNOWN);
            return osvPackage;
        }

        private List<OsvSeverity> toOsv(Impact impact) {
            if (ObjectUtils.isEmpty(impact)) {
                return null;
            }

            List<OsvSeverity> severities = new ArrayList<>();
            if (!ObjectUtils.isEmpty(impact.baseMetricV2()) && !ObjectUtils.isEmpty(impact.baseMetricV2().cvssV2())
                    && !StringUtils.isEmpty(impact.baseMetricV2().cvssV2().vectorString())) {
                var severity = new OsvSeverity();
                severity.setType(ScoringSystem.CVSS_V2);
                severity.setScore(impact.baseMetricV2().cvssV2().vectorString());
                severities.add(severity);
            }
            if (!ObjectUtils.isEmpty(impact.baseMetricV3()) && !ObjectUtils.isEmpty(impact.baseMetricV3().cvssV3())
                    && !StringUtils.isEmpty(impact.baseMetricV3().cvssV3().vectorString())) {
                var severity = new OsvSeverity();
                severity.setType(ScoringSystem.CVSS_V3);
                severity.setScore(impact.baseMetricV3().cvssV3().vectorString());
                severities.add(severity);
            }
            return severities;
        }

        private OsvReference toOsv(Reference reference) {
            var url = reference.url().replaceAll("[\"\\\\]", "").strip();
            if (StringUtils.isBlank(url) || !isValidUrl(url)) {
                return null;
            }

            var osvReference = new OsvReference();
            osvReference.setType(ReferenceType.WEB);
            osvReference.setUrl(url);
            return osvReference;
        }

        private static boolean isValidUrl(String url) {
            try {
                return Objects.nonNull(new URI(url).getHost());
            } catch (Exception e) {
                return false;
            }
        }

        /**
         * Parse Vtopia timestamp to ISO-8601 timestamp.
         * <p>1970-01-01 00:00:00 -> 1970-01-01T00:00:00Z</p>
         * <p>1970-01-01 00:00 -> 1970-01-01T00:00:00Z</p>
         *
         * @param timestamp Vtopia timestamp
         * @return ISO-8601 timestamp
         */
        private static String convertVtopiaTimestamp(String timestamp) {
            var formatter = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
            formatter.setTimeZone(TimeZone.getTimeZone("GMT+8"));
            try {
                return formatter.parse(timestamp).toInstant().toString();
            } catch (ParseException e) {
                formatter = new SimpleDateFormat("yyyy-MM-dd hh:mm");
                formatter.setTimeZone(TimeZone.getTimeZone("GMT+8"));
                try {
                    return formatter.parse(timestamp).toInstant().toString();
                } catch (ParseException e1) {
                    // If failed to parse the timestamp, return null as an alternative.
                    return null;
                }
            }
        }
    }
}
