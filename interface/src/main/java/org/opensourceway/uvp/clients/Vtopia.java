package org.opensourceway.uvp.clients;

import org.opensourceway.uvp.pojo.vtopia.VtopiaResp;

/**
 * Client for retrieving data from Vtopia.
 */
public interface Vtopia {
    /**
     * Dump a batch of CVEs via Vtopia API.
     *
     * @param page     The page number.
     * @param pageSize The number of CVEs per page.
     * @return Vtopia-defined response.
     */
    VtopiaResp dumpCves(Integer page, Integer pageSize);
}
