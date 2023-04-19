package org.opensourceway.uvp.clients;

import org.opensourceway.uvp.pojo.nvd.cpematch.NvdCpeMatchResp;
import org.opensourceway.uvp.pojo.nvd.cve.NvdCveResp;

/**
 * Client for retrieving data from NVD.
 * <p><a href="https://nvd.nist.gov/developers/vulnerabilities">NVD Vuln API DOC</a></p>
 * <p><a href="https://nvd.nist.gov/developers/products">NVD CPE API DOC</a></p>
 */
public interface Nvd {

    /**
     * Dump a batch of CVEs via NVD API.
     * @param startIndex The index of the first CVE to be returned in the response data.
     * @return NVD-defined response.
     */
    NvdCveResp dumpCves(Integer startIndex);

    /**
     * Dump a batch of CPEs via NVD API.
     * @param startIndex The index of the first CPE to be returned in the response data.
     * @return NVD-defined response.
     */
    NvdCpeMatchResp dumpCpes(Integer startIndex);
}
