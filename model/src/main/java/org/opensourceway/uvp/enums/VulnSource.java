package org.opensourceway.uvp.enums;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public enum VulnSource {
    // Aggregated Vulnerabilities from open source databases.
    AGGREGATED(null, VulnSourceCategory.AGGREGATED),

    // Aggregated Vulnerabilities from open source and private databases.
    AGGREGATED_WITH_PRIVATE(null, VulnSourceCategory.AGGREGATED),

    OSV(0, VulnSourceCategory.PUBLIC),

    NVD(1, VulnSourceCategory.PUBLIC),

    OSS_INDEX(2, VulnSourceCategory.PUBLIC),

    VTOPIA(2, VulnSourceCategory.PRIVATE),

    PRISM_7_CAI(2, VulnSourceCategory.PRIVATE),
    ;

    /**
     * The priority of the vuln source. A smaller number indicates a higher priority.
     * <p>Used by aggregator.</p>
     */
    private final Integer priority;

    /**
     * The category of vuln source.
     *
     * @see VulnSourceCategory
     */
    private final VulnSourceCategory category;

    VulnSource(Integer priority, VulnSourceCategory category) {
        this.priority = priority;
        this.category = category;
    }

    public Integer getPriority() {
        return priority;
    }

    public VulnSourceCategory getCategory() {
        return category;
    }

    public boolean hasHigherPriority(VulnSource other) {
        return this.priority < other.priority;
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
