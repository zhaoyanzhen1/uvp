package org.opensourceway.uvp.enums;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public enum VulnSource {
    // Aggregated Vulnerabilities from open source databases.
    AGGREGATED(VulnSourceCategory.AGGREGATED),

    // Aggregated Vulnerabilities from open source and private databases.
    AGGREGATED_WITH_PRIVATE(VulnSourceCategory.AGGREGATED),

    OSV(VulnSourceCategory.PUBLIC),

    NVD(VulnSourceCategory.PUBLIC),

    OSS_INDEX(VulnSourceCategory.PUBLIC),

    VTOPIA(VulnSourceCategory.PRIVATE),
    ;

    /**
     * The category of vuln source.
     *
     * @see VulnSourceCategory
     */
    private final VulnSourceCategory category;

    VulnSource(VulnSourceCategory category) {
        this.category = category;
    }

    public VulnSourceCategory getCategory() {
        return category;
    }

    public static List<VulnSource> getPublicSource() {
        return Arrays.stream(VulnSource.values())
                .filter(it -> VulnSourceCategory.PUBLIC.equals(it.getCategory()))
                .toList();
    }

    public static List<VulnSource> getPublicAndPrivateSource() {
        return Arrays.stream(VulnSource.values())
                .filter(it -> VulnSourceCategory.PUBLIC.equals(it.getCategory())
                        || VulnSourceCategory.PRIVATE.equals(it.getCategory()))
                .toList();
    }

    @Converter(autoApply = true)
    public static class VulnSourceConverter implements AttributeConverter<VulnSource, String> {

        @Override
        public String convertToDatabaseColumn(VulnSource eventType) {
            return Objects.nonNull(eventType) ? eventType.name() : null;
        }

        @Override
        public VulnSource convertToEntityAttribute(String dbData) {
            if (Objects.isNull(dbData)) {
                return null;
            }
            return VulnSource.valueOf(dbData);
        }
    }

    public enum VulnSourceCategory {
        AGGREGATED,

        PUBLIC,

        PRIVATE
    }
}
