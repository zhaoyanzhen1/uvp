package org.opensourceway.uvp.pojo.vtopia;

import com.fasterxml.jackson.annotation.JsonValue;

public enum UpdateType {
    INSERT("insert"),

    UPDATE("update");

    private final String type;

    UpdateType(String type) {
        this.type = type;
    }

    @JsonValue
    public String getType() {
        return type;
    }
}
