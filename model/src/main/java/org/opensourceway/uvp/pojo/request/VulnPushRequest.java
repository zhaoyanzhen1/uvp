package org.opensourceway.uvp.pojo.request;

import org.opensourceway.uvp.enums.VulnSource;
import org.opensourceway.uvp.pojo.osv.OsvVulnerability;

public class VulnPushRequest {
    private VulnSource source;

    private OsvVulnerability vuln;

    public VulnPushRequest(VulnSource source, OsvVulnerability vuln) {
        this.source = source;
        this.vuln = vuln;
    }

    public VulnSource getSource() {
        return source;
    }

    public void setSource(VulnSource source) {
        this.source = source;
    }

    public OsvVulnerability getVuln() {
        return vuln;
    }

    public void setVuln(OsvVulnerability vuln) {
        this.vuln = vuln;
    }
}
