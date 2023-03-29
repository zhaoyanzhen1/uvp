package org.opensourceway.uvp.clients.provider.ossindex.merger;

import org.opensourceway.uvp.clients.provider.merger.PartialVulnMerger;
import org.opensourceway.uvp.pojo.osv.OsvAffected;
import org.opensourceway.uvp.pojo.osv.OsvVulnerability;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class OssIndexMerger implements PartialVulnMerger {
    @Override
    public OsvVulnerability merge(List<OsvVulnerability> vulns) {
        // Merge versions of the same affected packages.
        var osvAffectedMerged = vulns.stream()
                .map(OsvVulnerability::getAffected)
                .flatMap(List::stream)
                .collect(Collectors.groupingBy(OsvAffected::getPkg, Collectors.toList()))
                .values()
                .stream()
                .map(osvAffectedList -> {
                    var result = new OsvAffected();
                    result.setPkg(osvAffectedList.get(0).getPkg());
                    result.setVersions(osvAffectedList.stream()
                            .map(OsvAffected::getVersions)
                            .flatMap(List::stream)
                            .distinct().toList());
                    return result;
                })
                .toList();

        var vuln = vulns.get(0);
        vuln.setAffected(osvAffectedMerged);
        return vuln;
    }
}
