package org.opensourceway.uvp.enums;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public enum VulnSource {
    // Aggregated Vulnerabilities from open source databases.
    UVP(VulnSourceCategory.AGGREGATED, true),

    // Aggregated Vulnerabilities from open source and private databases.
    UVP_ALL(VulnSourceCategory.AGGREGATED, true),

    OSV(VulnSourceCategory.PUBLIC, false),

    NVD(VulnSourceCategory.PUBLIC, false),

    OSS_INDEX(VulnSourceCategory.PUBLIC, false),

    VTOPIA(VulnSourceCategory.PRIVATE, true),
    ;

    /**
     * The category of vuln source.
     *
     * @see VulnSourceCategory
     */
    private final VulnSourceCategory category;

    private final boolean pushable;

    VulnSource(VulnSourceCategory category, boolean pushable) {
        this.category = category;
        this.pushable = pushable;
    }

    public VulnSourceCategory getCategory() {
        return category;
    }

    public boolean isPushable() {
        return pushable;
    }

    public static List<VulnSource> getPublicSources() {
        return Arrays.stream(VulnSource.values())
                .filter(it -> VulnSourceCategory.PUBLIC.equals(it.getCategory()))
                .toList();
    }

    public static List<VulnSource> getPublicAndUnpushablePrivateSources() {
        return Arrays.stream(VulnSource.values())
                .filter(it -> VulnSourceCategory.PUBLIC.equals(it.getCategory())
                        || (VulnSourceCategory.PRIVATE.equals(it.getCategory()) && !it.isPushable()))
                .toList();
    }

    public static List<VulnSource> getPushableSources() {
        return Arrays.stream(VulnSource.values())
                .filter(VulnSource::isPushable)
                .toList();
    }

    public static List<VulnSource> getUnpushableSources() {
        return Arrays.stream(VulnSource.values())
                .filter(it -> !it.isPushable())
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
