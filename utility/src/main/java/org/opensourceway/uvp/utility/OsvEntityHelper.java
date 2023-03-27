package org.opensourceway.uvp.utility;

import org.apache.commons.lang3.StringUtils;
import org.opensourceway.uvp.constant.OsvConstant;
import org.opensourceway.uvp.dao.VulnerabilityRepository;
import org.opensourceway.uvp.entity.AffectedEvent;
import org.opensourceway.uvp.entity.AffectedPackage;
import org.opensourceway.uvp.entity.AffectedRange;
import org.opensourceway.uvp.entity.Alias;
import org.opensourceway.uvp.entity.Credit;
import org.opensourceway.uvp.entity.Reference;
import org.opensourceway.uvp.entity.Severity;
import org.opensourceway.uvp.entity.Vulnerability;
import org.opensourceway.uvp.enums.CvssSeverity;
import org.opensourceway.uvp.enums.EventType;
import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.pojo.osv.OsvAffected;
import org.opensourceway.uvp.pojo.osv.OsvCredit;
import org.opensourceway.uvp.pojo.osv.OsvEvent;
import org.opensourceway.uvp.pojo.osv.OsvPackage;
import org.opensourceway.uvp.pojo.osv.OsvRange;
import org.opensourceway.uvp.pojo.osv.OsvReference;
import org.opensourceway.uvp.pojo.osv.OsvSeverity;
import org.opensourceway.uvp.pojo.osv.OsvVulnerability;
import org.opensourceway.uvp.pojo.response.SearchResp;
import org.opensourceway.uvp.pojo.response.VulnDetailResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.sql.Timestamp;
import java.text.MessageFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Stack;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class OsvEntityHelper {

    private static final Logger logger = LoggerFactory.getLogger(OsvEntityHelper.class);

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    public Vulnerability toVuln(VulnSource source, OsvVulnerability osvVulnerability) {
        if (Objects.isNull(osvVulnerability)) {
            return null;
        }

        var vuln = new Vulnerability();
        vuln.setSource(source);
        return toEntity(osvVulnerability, vuln);
    }

    private Vulnerability toEntity(OsvVulnerability osvVuln, Vulnerability vuln) {
        if (Objects.isNull(osvVuln)) {
            return null;
        }

        vuln.setSchemaVersion(osvVuln.getSchemaVersion());
        vuln.setVulnId(osvVuln.getId());
        vuln.setAliases(Objects.isNull(osvVuln.getAliases()) ? new ArrayList<>()
                : osvVuln.getAliases().stream()
                .map(it -> toEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        vuln.setRelated(osvVuln.getRelated());
        vuln.setModified(Objects.isNull(osvVuln.getModified()) ? null
                : Timestamp.from(Instant.parse(osvVuln.getModified())));
        vuln.setPublished(Objects.isNull(osvVuln.getPublished()) ? null
                : Timestamp.from(Instant.parse(osvVuln.getPublished())));
        vuln.setWithdrawn(Objects.isNull(osvVuln.getWithdrawn()) ? null
                : Timestamp.from(Instant.parse(osvVuln.getWithdrawn())));
        vuln.setSummary(osvVuln.getSummary());
        vuln.setDetail(osvVuln.getDetails());
        vuln.setDatabaseSpecific(osvVuln.getDatabaseSpecific());
        vuln.setSeverities(Objects.isNull(osvVuln.getSeverity()) ? new ArrayList<>()
                : osvVuln.getSeverity().stream()
                .map(it -> toEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        vuln.setReferences(Objects.isNull(osvVuln.getReferences()) ? new ArrayList<>()
                : osvVuln.getReferences().stream()
                .map(it -> toEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        vuln.setCredits(Objects.isNull(osvVuln.getCredits()) ? new ArrayList<>()
                : osvVuln.getCredits().stream()
                .map(it -> toEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        vuln.setAffectedPackages(Objects.isNull(osvVuln.getAffected()) ? new ArrayList<>()
                : osvVuln.getAffected().stream()
                .map(it -> toEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        return vuln;
    }

    private Severity toEntity(OsvSeverity osvSeverity, Vulnerability vuln) {
        if (Objects.isNull(osvSeverity)) {
            return null;
        }

        var entity = new Severity();
        entity.setScoringSystem(osvSeverity.getType());
        Double score = CvssUtil.calculateScore(osvSeverity.getScore());
        entity.setScore(score);
        entity.setVector(osvSeverity.getScore());
        entity.setSeverity(CvssSeverity.calculateCvssSeverity(osvSeverity.getType(), score));
        entity.setVulnerability(vuln);
        return entity;
    }

    private Reference toEntity(OsvReference osvReference, Vulnerability vuln) {
        if (Objects.isNull(osvReference) || Objects.isNull(osvReference.getType())
                || Objects.isNull(osvReference.getUrl())) {
            return null;
        }

        var entity = new Reference();
        entity.setType(osvReference.getType());
        entity.setUrl(osvReference.getUrl());
        entity.setVulnerability(vuln);
        return entity;
    }

    private Credit toEntity(OsvCredit osvCredit, Vulnerability vuln) {
        if (Objects.isNull(osvCredit) || Objects.isNull(osvCredit.getName())
                || ObjectUtils.isEmpty(osvCredit.getContact())) {
            return null;
        }

        var entity = new Credit();
        entity.setName(osvCredit.getName());
        entity.setContacts(osvCredit.getContact());
        entity.setVulnerability(vuln);
        return entity;
    }

    private AffectedPackage toEntity(OsvAffected osvAffected, Vulnerability vuln) {
        if (Objects.isNull(osvAffected)) {
            return null;
        }

        var entity = new AffectedPackage();
        entity.setEcosystem(osvAffected.getPkg().getEcosystem());
        entity.setName(osvAffected.getPkg().getName());
        entity.setPurl(osvAffected.getPkg().getPurl());
        entity.setVersions(Objects.isNull(osvAffected.getVersions()) ? new ArrayList<>() : osvAffected.getVersions());
        entity.setEcosystemSpecific(osvAffected.getEcosystemSpecific());
        entity.setDatabaseSpecific(osvAffected.getDatabaseSpecific());
        entity.setRanges(Objects.isNull(osvAffected.getRanges()) ? new ArrayList<>()
                : osvAffected.getRanges().stream()
                .map(it -> toEntity(it, entity)).filter(Objects::nonNull).collect(Collectors.toList()));
        entity.setVulnerability(vuln);
        return entity;
    }

    private AffectedRange toEntity(OsvRange osvRange, AffectedPackage affectedPackage) {
        if (Objects.isNull(osvRange)) {
            return null;
        }

        var entity = new AffectedRange();
        entity.setType(osvRange.getType());
        entity.setRepo(osvRange.getRepo());
        entity.setEvents(Objects.isNull(osvRange.getEvents()) ? new ArrayList<>()
                : osvRange.getEvents().stream()
                .map(it -> toEntity(it, entity, osvRange.getEvents().indexOf(it)))
                .filter(Objects::nonNull).collect(Collectors.toList()));
        entity.setAffectedPackage(affectedPackage);
        return entity;
    }

    private AffectedEvent toEntity(OsvEvent osvEvent, AffectedRange affectedRange, Integer order) {
        if (Objects.isNull(osvEvent)) {
            return null;
        }

        var entity = new AffectedEvent();
        if (osvEvent.size() != 1) {
            throw new RuntimeException("An osv event must only contains one event. Invalid record: %s"
                    .formatted(osvEvent));
        }
        entity.setType(osvEvent.keySet().stream().toList().get(0));
        entity.setValue(osvEvent.values().stream().toList().get(0));
        entity.setEventOrder(order);
        entity.setRange(affectedRange);
        return entity;
    }

    private Alias toEntity(String alias, Vulnerability vuln) {
        if (Objects.isNull(alias)) {
            return null;
        }

        var entity = new Alias();
        entity.setAlias(alias);
        entity.setVulnerability(vuln);
        return entity;
    }

    public OsvEvent toVo(AffectedEvent affectedEvent) {
        var vo = new OsvEvent();
        vo.put(affectedEvent.getType(), affectedEvent.getValue());
        return vo;
    }

    private OsvAffected toVo(AffectedPackage affectedPackage) {
        var vo = new OsvAffected();
        var osvPackage = new OsvPackage();
        osvPackage.setEcosystem(affectedPackage.getEcosystem());
        osvPackage.setName(affectedPackage.getName());
        osvPackage.setPurl(affectedPackage.getPurl());
        vo.setPkg(osvPackage);
        vo.setRanges(affectedPackage.getRanges().stream().map(this::toVo).toList());
        vo.setVersions(affectedPackage.getVersions());
        vo.setDatabaseSpecific(affectedPackage.getDatabaseSpecific());
        vo.setEcosystemSpecific(affectedPackage.getEcosystemSpecific());
        return vo;
    }

    private OsvRange toVo(AffectedRange affectedRange) {
        var vo = new OsvRange();
        vo.setType(affectedRange.getType());
        vo.setRepo(affectedRange.getRepo());
        vo.setEvents(affectedRange.getEvents().stream().map(this::toVo).toList());
        vo.setDatabaseSpecific(affectedRange.getDatabaseSpecific());
        return vo;
    }

    private OsvCredit toVo(Credit credit) {
        var vo = new OsvCredit();
        vo.setName(credit.getName());
        vo.setContact(credit.getContacts());
        return vo;
    }

    private OsvReference toVo(Reference reference) {
        var vo = new OsvReference();
        vo.setType(reference.getType());
        vo.setUrl(reference.getUrl());
        return vo;
    }

    private OsvSeverity toVo(Severity severity) {
        var vo = new OsvSeverity();
        vo.setType(severity.getScoringSystem());
        vo.setScore(severity.getVector());
        return vo;
    }

    public OsvVulnerability toVo(Vulnerability vuln) {
        var vo = new OsvVulnerability();
        vo.setSchemaVersion(vuln.getSchemaVersion());
        vo.setId(vuln.getVulnId());
        vo.setModified(Objects.isNull(vuln.getModified()) ? null : vuln.getModified().toInstant().toString());
        vo.setPublished(Objects.isNull(vuln.getPublished()) ? null : vuln.getPublished().toInstant().toString());
        vo.setWithdrawn(Objects.isNull(vuln.getWithdrawn()) ? null : vuln.getWithdrawn().toInstant().toString());
        vo.setAliases(vuln.getAliases().stream().map(Alias::getAlias).toList());
        vo.setRelated(vuln.getRelated());
        vo.setSummary(vuln.getSummary());
        vo.setDetails(vuln.getDetail());
        vo.setSeverity(vuln.getSeverities().stream().map(this::toVo).toList());
        vo.setAffected(vuln.getAffectedPackages().stream().map(this::toVo).toList());
        vo.setReferences(vuln.getReferences().stream().map(this::toVo).toList());
        vo.setCredits(vuln.getCredits().stream().map(this::toVo).toList());
        vo.setDatabaseSpecific(vuln.getDatabaseSpecific());
        return vo;
    }

    public Vulnerability copyEntity(Vulnerability old, VulnSource source) {
        if (Objects.isNull(old)) {
            return null;
        }

        var vuln = new Vulnerability();
        vuln.setSource(source);
        vuln.setSchemaVersion(old.getSchemaVersion());
        vuln.setVulnId(old.getVulnId());
        vuln.setRelated(old.getRelated());
        vuln.setModified(old.getModified());
        vuln.setPublished(old.getPublished());
        vuln.setWithdrawn(old.getWithdrawn());
        vuln.setSummary(old.getSummary());
        vuln.setDetail(old.getDetail());
        vuln.setDatabaseSpecific(old.getDatabaseSpecific());
        vuln.setAliases(Objects.isNull(old.getAliases()) ? new ArrayList<>()
                : old.getAliases().stream()
                .map(it -> copyEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        vuln.setSeverities(Objects.isNull(old.getSeverities()) ? new ArrayList<>()
                : old.getSeverities().stream()
                .map(it -> copyEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        vuln.setReferences(Objects.isNull(old.getReferences()) ? new ArrayList<>()
                : old.getReferences().stream()
                .map(it -> copyEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        vuln.setCredits(Objects.isNull(old.getCredits()) ? new ArrayList<>()
                : old.getCredits().stream()
                .map(it -> copyEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        vuln.setAffectedPackages(Objects.isNull(old.getAffectedPackages()) ? new ArrayList<>()
                : old.getAffectedPackages().stream()
                .map(it -> copyEntity(it, vuln)).filter(Objects::nonNull).collect(Collectors.toList()));
        return vuln;
    }

    private Severity copyEntity(Severity old, Vulnerability vuln) {
        if (Objects.isNull(old)) {
            return null;
        }

        var entity = new Severity();
        entity.setScoringSystem(old.getScoringSystem());
        entity.setScore(old.getScore());
        entity.setVector(old.getVector());
        entity.setSeverity(old.getSeverity());
        entity.setVulnerability(vuln);
        return entity;
    }

    private Reference copyEntity(Reference old, Vulnerability vuln) {
        if (Objects.isNull(old)) {
            return null;
        }

        var entity = new Reference();
        entity.setType(old.getType());
        entity.setUrl(old.getUrl());
        entity.setVulnerability(vuln);
        return entity;
    }

    private Credit copyEntity(Credit old, Vulnerability vuln) {
        if (Objects.isNull(old)) {
            return null;
        }

        var entity = new Credit();
        entity.setName(old.getName());
        entity.setContacts(old.getContacts());
        entity.setVulnerability(vuln);
        return entity;
    }

    private AffectedPackage copyEntity(AffectedPackage old, Vulnerability vuln) {
        if (Objects.isNull(old)) {
            return null;
        }

        var entity = new AffectedPackage();
        entity.setEcosystem(old.getEcosystem());
        entity.setName(old.getName());
        entity.setPurl(old.getPurl());
        entity.setVersions(old.getVersions());
        entity.setEcosystemSpecific(old.getEcosystemSpecific());
        entity.setDatabaseSpecific(old.getDatabaseSpecific());
        entity.setRanges(Objects.isNull(old.getRanges()) ? new ArrayList<>()
                : old.getRanges().stream()
                .map(it -> copyEntity(it, entity)).filter(Objects::nonNull).collect(Collectors.toList()));
        entity.setVulnerability(vuln);
        return entity;
    }

    private AffectedRange copyEntity(AffectedRange old, AffectedPackage affectedPackage) {
        if (Objects.isNull(old)) {
            return null;
        }

        var entity = new AffectedRange();
        entity.setType(old.getType());
        entity.setRepo(old.getRepo());
        entity.setEvents(Objects.isNull(old.getEvents()) ? new ArrayList<>()
                : old.getEvents().stream()
                .map(it -> copyEntity(it, entity)).filter(Objects::nonNull)
                .sorted(Comparator.comparing(AffectedEvent::getEventOrder))
                .collect(Collectors.toList()));
        entity.setAffectedPackage(affectedPackage);
        return entity;
    }

    private AffectedEvent copyEntity(AffectedEvent old, AffectedRange affectedRange) {
        if (Objects.isNull(old)) {
            return null;
        }

        var entity = new AffectedEvent();
        entity.setType(old.getType());
        entity.setValue(old.getValue());
        entity.setEventOrder(old.getEventOrder());
        entity.setRange(affectedRange);
        return entity;
    }

    private Alias copyEntity(Alias old, Vulnerability vuln) {
        if (Objects.isNull(old)) {
            return null;
        }

        var entity = new Alias();
        entity.setAlias(old.getAlias());
        entity.setVulnerability(vuln);
        return entity;
    }

    public SearchResp.SearchRespObj toSearchObj(Vulnerability vuln) {
        if (Objects.isNull(vuln)) {
            return null;
        }

        var obj = new SearchResp.SearchRespObj();

        obj.setVulnId(vuln.getVulnId());
        obj.setSummary(getSummary(vuln));
        obj.setScore(ObjectUtils.isEmpty(vuln.getSeverities()) ? null : vuln.getSeverities().get(0).getScore());
        obj.setSeverity(ObjectUtils.isEmpty(vuln.getSeverities()) ? null : vuln.getSeverities().get(0).getSeverity());
        obj.setPublished(Objects.isNull(vuln.getPublished()) ? null : vuln.getPublished().toInstant().toString());
        obj.setModified(Objects.isNull(vuln.getModified()) ? null : vuln.getModified().toInstant().toString());
        obj.setAffectedPackages(getAffectedPackages(vuln));
        obj.setFixed(isFixed(vuln));

        return obj;
    }

    private String getSummary(Vulnerability vuln) {
        if (StringUtils.isNotBlank(vuln.getSummary())) {
            return vuln.getSummary();
        }

        if (StringUtils.isNotBlank(vuln.getDetail())) {
            return vuln.getDetail().length() > 100 ? vuln.getDetail().substring(0, 100) + "..." : vuln.getDetail();
        }

        return "";
    }

    private List<String> getAffectedPackages(Vulnerability vuln) {
        return ObjectUtils.isEmpty(vuln.getAffectedPackages()) ? null : vuln.getAffectedPackages().stream()
                .map(it -> StringUtils.isBlank(it.getPurl()) ? it.getName() : it.getPurl()).distinct().toList();
    }

    private Boolean isFixed(Vulnerability vuln) {
        if (ObjectUtils.isEmpty(vuln.getAffectedPackages())) {
            return null;
        }

        return vuln.getAffectedPackages()
                .stream()
                // If any fixed or limit version is found in any affected package, treat it as fixed.
                .anyMatch(it -> it.getRanges()
                        .stream()
                        .map(AffectedRange::getEvents)
                        .flatMap(List::stream)
                        .anyMatch(event -> EventType.isFixed(event.getType())));
    }

    public VulnDetailResp toDetail(Vulnerability vuln) {
        if (Objects.isNull(vuln)) {
            return null;
        }

        var resp = new VulnDetailResp();

        resp.setAliases(vuln.getAliases().stream().map(Alias::getAlias).toList());
        resp.setPublished(Objects.isNull(vuln.getPublished()) ? null : vuln.getPublished().toInstant().toString());
        resp.setModified(Objects.isNull(vuln.getModified()) ? null : vuln.getModified().toInstant().toString());
        resp.setDetail(vuln.getDetail());
        resp.setScore(ObjectUtils.isEmpty(vuln.getSeverities()) ? null : vuln.getSeverities().get(0).getScore());
        resp.setSeverity(ObjectUtils.isEmpty(vuln.getSeverities()) ? null : vuln.getSeverities().get(0).getSeverity());
        resp.setVector(ObjectUtils.isEmpty(vuln.getSeverities()) ? null : vuln.getSeverities().get(0).getVector());
        resp.setReferences(vuln.getReferences().stream().map(Reference::getUrl).toList());
        resp.setAffectedPackages(vuln.getAffectedPackages().stream().map(this::getAffectedPackage).toList());

        return resp;
    }

    private VulnDetailResp.AffectedPackage getAffectedPackage(AffectedPackage pkg) {
        var obj = new VulnDetailResp.AffectedPackage();

        obj.setPkg(StringUtils.isEmpty(pkg.getPurl())
                ? MessageFormat.format("%s/%s", pkg.getEcosystem().getEcosystem(), pkg.getName())
                : pkg.getPurl());
        obj.setAffectedRanges(ObjectUtils.isEmpty(pkg.getRanges()) ? null
                : pkg.getRanges().stream().map(this::getAffectedRange)
                .filter(Objects::nonNull).flatMap(List::stream).filter(Objects::nonNull)
                .sorted(Comparator.comparing(VulnDetailResp.AffectedPackage.AffectedRange::getFixed,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .toList());
        obj.setAffectedVersions(pkg.getVersions());

        return obj;
    }

    private List<VulnDetailResp.AffectedPackage.AffectedRange> getAffectedRange(AffectedRange range) {
        if (Objects.isNull(range) || ObjectUtils.isEmpty(range.getEvents())) {
            return null;
        }

        var result = new ArrayList<VulnDetailResp.AffectedPackage.AffectedRange>();
        var introducedStack = new Stack<String>();
        range.getEvents().forEach(event -> {
            if (Objects.isNull(event)) {
                return;
            }

            if (EventType.INTRODUCED.equals(event.getType()) && Objects.nonNull(event.getValue())) {
                introducedStack.push(event.getValue());
                return;
            }

            if (EventType.isFixed(event.getType())) {
                if (introducedStack.empty()) {
                    result.add(new VulnDetailResp.AffectedPackage.AffectedRange(
                            VulnDetailResp.AffectedPackage.AffectedRange.FIXED_ONLY.formatted(event.getValue()),
                            event.getValue()));
                    return;
                }
                if (OsvConstant.DEFAULT_INTRODUCED_VERSION.equals(introducedStack.peek())) {
                    introducedStack.pop();
                    result.add(new VulnDetailResp.AffectedPackage.AffectedRange(
                            VulnDetailResp.AffectedPackage.AffectedRange.FIXED_ONLY.formatted(event.getValue()),
                            event.getValue()));
                    return;
                }
                result.add(new VulnDetailResp.AffectedPackage.AffectedRange(
                        VulnDetailResp.AffectedPackage.AffectedRange.INTRO_AND_FIXED
                                .formatted(introducedStack.pop(), event.getValue()), event.getValue()));
                return;
            }

            if (EventType.LAST_AFFECTED.equals(event.getType())) {
                if (introducedStack.empty()) {
                    result.add(new VulnDetailResp.AffectedPackage.AffectedRange(
                            VulnDetailResp.AffectedPackage.AffectedRange.LAST_AFFECTED_ONLY.formatted(event.getValue()),
                            null));
                    return;
                }
                if (OsvConstant.DEFAULT_INTRODUCED_VERSION.equals(introducedStack.peek())) {
                    introducedStack.pop();
                    result.add(new VulnDetailResp.AffectedPackage.AffectedRange(
                            VulnDetailResp.AffectedPackage.AffectedRange.LAST_AFFECTED_ONLY.formatted(event.getValue()),
                            null));
                    return;
                }
                result.add(new VulnDetailResp.AffectedPackage.AffectedRange(
                        VulnDetailResp.AffectedPackage.AffectedRange.INTRO_AND_LAST_AFFECTED
                                .formatted(introducedStack.pop(), event.getValue()), null));
            }
        });

        introducedStack.forEach(event -> result.add(new VulnDetailResp.AffectedPackage.AffectedRange(
                VulnDetailResp.AffectedPackage.AffectedRange.INTRO_ONLY.formatted(event), null)));
        return result;
    }

    private Vulnerability update(Vulnerability existVuln, Vulnerability newVuln) {
        if (Objects.isNull(existVuln)) {
            return newVuln;
        }

        if (Objects.equals(existVuln, newVuln)) {
            return null;
        }

        existVuln.setSchemaVersion(newVuln.getSchemaVersion());
        existVuln.setRelated(newVuln.getRelated());
        existVuln.setModified(newVuln.getModified());
        existVuln.setPublished(newVuln.getPublished());
        existVuln.setWithdrawn(newVuln.getWithdrawn());
        existVuln.setSummary(newVuln.getSummary());
        existVuln.setDetail(newVuln.getDetail());
        existVuln.setDatabaseSpecific(newVuln.getDatabaseSpecific());

        existVuln.getAliases().stream().filter(it -> !newVuln.getAliases().contains(it)).toList()
                .forEach(existVuln::removeAlias);
        newVuln.getAliases().forEach(existVuln::addAlias);

        existVuln.getSeverities().stream().filter(it -> !newVuln.getSeverities().contains(it)).toList()
                .forEach(existVuln::removeSeverity);
        newVuln.getSeverities().forEach(existVuln::addSeverity);

        existVuln.getReferences().stream().filter(it -> !newVuln.getReferences().contains(it)).toList()
                .forEach(existVuln::removeReference);
        newVuln.getReferences().forEach(existVuln::addReference);

        existVuln.getCredits().stream().filter(it -> !newVuln.getCredits().contains(it)).toList()
                .forEach(existVuln::removeCredit);
        newVuln.getCredits().forEach(existVuln::addCredit);

        existVuln.getAffectedPackages().stream().filter(it -> !newVuln.getAffectedPackages().contains(it)).toList()
                .forEach(existVuln::removeAffectedPackage);
        newVuln.getAffectedPackages().forEach(existVuln::addAffectedPackage);

        return existVuln;
    }

    /**
     * Batch update existing vulnerabilities or insert new vulnerabilities.
     *
     * @param vulns new vulnerabilities.
     */
    public void batchUpsert(VulnSource vulnSource, List<Vulnerability> vulns) {
        var existVulns = vulnerabilityRepository
                .findBySourceAndVulnIds(vulnSource, vulns.stream().map(Vulnerability::getVulnId).toList())
                .stream()
                .collect(Collectors.toMap(Vulnerability::getVulnId, Function.identity()));
        var newVulns = vulns.stream().map(it -> update(existVulns.get(it.getVulnId()), it))
                .filter(Objects::nonNull)
                .toList();
        if (!ObjectUtils.isEmpty(newVulns)) {
            vulnerabilityRepository.saveAll(newVulns);
            logger.info("Upsert <{}> vulns", newVulns.size());
        }
    }
}
