package org.opensourceway.uvp.service;

import org.opensourceway.uvp.entity.Vulnerability;

import java.util.List;
import java.util.Map;

/**
 * Query local vuln database.
 */
public interface VulnLocalService {
    /**
     * Query vulnerabilities that affect the given package from local vuln databases.
     *
     * @param purl Package URL.
     * @return A list of vulnerabilities that affect the given PURL.
     */
    List<Vulnerability> query(String purl);

    /**
     * Batch query vulnerabilities that affect the given packages from local vuln databases.
     *
     * @param purls A list of Package URLs.
     * @return PURLs and their corresponding affecting vulnerabilities.
     */
    Map<String, List<Vulnerability>> queryBatch(List<String> purls);

    /**
     * Search vulnerabilities by the given parameters.
     *
     * @param keyword Search keyword.
     * @param limit   Limit of query result.
     * @param offset  Offset of query result.
     * @return A list of vulnerabilities that match the request.
     */
    List<Vulnerability> search(String keyword, Integer limit, Integer offset);

    /**
     * Query details of a vulnerability by the given vulnerability ID.
     * @param vulnId Vulnerability ID.
     * @return Vulnerability with the ID.
     */
    Vulnerability queryVulnDetail(String vulnId);
}
