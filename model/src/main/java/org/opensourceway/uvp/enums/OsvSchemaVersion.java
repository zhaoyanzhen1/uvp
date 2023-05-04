package org.opensourceway.uvp.enums;

import com.fasterxml.jackson.annotation.JsonValue;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.apache.commons.lang3.StringUtils;

import java.util.Objects;

public enum OsvSchemaVersion {
    V1_3_0("1.3.0"),

    V1_3_1("1.3.1"),

    V1_4_0("1.4.0"),

    V1_5_0("1.5.0"),
    ;

    private final String version;

    OsvSchemaVersion(String version) {
        this.version = version;
    }

    @JsonValue
    public String getVersion() {
        return version;
    }

    public static OsvSchemaVersion newestVersion() {
        return V1_5_0;
    }

    public static OsvSchemaVersion findByVersion(String version) {
        if (StringUtils.isEmpty(version)) {
            return null;
        }

        for (OsvSchemaVersion osvSchemaVersion : OsvSchemaVersion.values()) {
            if (StringUtils.equals(osvSchemaVersion.version, version)) {
                return osvSchemaVersion;
            }
        }

        return null;
    }

    @Converter(autoApply = true)
    public static class OsvSchemaVersionConverter implements AttributeConverter<OsvSchemaVersion, String> {

        @Override
        public String convertToDatabaseColumn(OsvSchemaVersion osvSchemaVersion) {
            return Objects.nonNull(osvSchemaVersion) ? osvSchemaVersion.getVersion() : null;
        }

        @Override
        public OsvSchemaVersion convertToEntityAttribute(String dbData) {
            if (Objects.isNull(dbData)) {
                return null;
            }
            return OsvSchemaVersion.findByVersion(dbData);
        }
    }
}
