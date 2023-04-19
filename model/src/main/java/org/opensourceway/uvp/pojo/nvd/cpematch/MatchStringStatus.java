package org.opensourceway.uvp.pojo.nvd.cpematch;

import com.fasterxml.jackson.annotation.JsonValue;

public enum MatchStringStatus {
    ACTIVE("Active"),

    INACTIVE("Inactive");

    private final String status;

    MatchStringStatus(String status) {
        this.status = status;
    }

    @JsonValue
    public String getStatus() {
        return status;
    }
}
