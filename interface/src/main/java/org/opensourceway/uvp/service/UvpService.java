package org.opensourceway.uvp.service;

import org.opensourceway.uvp.pojo.osv.OsvVulnerability;
import org.opensourceway.uvp.pojo.request.SearchRequest;
import org.opensourceway.uvp.pojo.response.PackageVulns;
import org.opensourceway.uvp.pojo.response.SearchResp;
import org.opensourceway.uvp.pojo.response.VulnDetailResp;

import java.util.List;

public interface UvpService {
    /**
     * Query vulnerabilities that affect the given package from local database.
     *
     * @param purl Package URL.
     * @return A list of osv-schema vulnerabilities.
     */
    List<OsvVulnerability> query(String purl);

    /**
     * Batch query vulnerabilities that affect the given packages from local database.
     *
     * @param purls A list of Package URLs.
     * @return A list whose element consists of each given package and its affected vulnerabilities.
     */
    List<PackageVulns> queryBatch(List<String> purls);

    /**
     * Batch import purls to local database.
     *
     * @param purls A list of Package URLs.
     */
    void importBatch(List<String> purls);

    /**
     * Search vulnerabilities by the given parameters.
     *
     * @param request {@link SearchRequest}.
     * @return {@link SearchResp}.
     */
    SearchResp search(SearchRequest request);

    /**
     * Query details of a vulnerability by ID.
     *
     * @param vulnId A vulnerability ID.
     * @return {@link SearchResp}.
     */
    VulnDetailResp queryVulnDetail(String vulnId);
}
