package org.opensourceway.uvp.service;

import org.opensourceway.uvp.pojo.osv.OsvVulnerability;
import org.opensourceway.uvp.pojo.response.PackageVulns;

import java.util.List;

/**
 * Query local vuln database.
 */
public interface VulnLocalService {
    /**
     * Query vulnerabilities that affect the given package from local vuln databases.
     *
     * @param purl Package URL.
     * @return A list of osv-schema vulnerabilities.
     */
    List<OsvVulnerability> query(String purl);

    /**
     * Batch query vulnerabilities that affect the given packages from local vuln databases.
     *
     * @param purls A list of Package URLs.
     * @return A list whose element consists of each given package and its affected vulnerabilities.
     */
    List<PackageVulns> queryBatch(List<String> purls);
}
