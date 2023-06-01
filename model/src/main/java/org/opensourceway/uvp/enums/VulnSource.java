package org.opensourceway.uvp.enums;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

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

    private static final List<VulnSource> PUBLIC_SOURCES = Arrays.stream(VulnSource.values())
            .filter(it -> VulnSourceCategory.PUBLIC.equals(it.getCategory()))
            .toList();

    private static final List<VulnSource> PUBLIC_OR_UNPUSHABLE_PRIVATE_SOURCES = Arrays.stream(VulnSource.values())
            .filter(it -> VulnSourceCategory.PUBLIC.equals(it.getCategory())
                    || (VulnSourceCategory.PRIVATE.equals(it.getCategory()) && !it.isPushable()))
            .toList();

    private static final List<VulnSource> PUSHABLE_SOURCES = Arrays.stream(VulnSource.values())
            .filter(VulnSource::isPushable)
            .toList();

    private static final List<VulnSource> UNPUSHABLE_SOURCES = Arrays.stream(VulnSource.values())
            .filter(Predicate.not(VulnSource::isPushable))
            .toList();

    private static final List<VulnSource> PUBLIC_PUSHABLE_SOURCES = Arrays.stream(VulnSource.values())
            .filter(VulnSource::isPushable)
            .filter(source -> Objects.equals(source.category, VulnSourceCategory.PUBLIC)
                    || Objects.equals(VulnSource.UVP, source))
            .toList();

    private static final List<VulnSource> PRIVATE_PUSHABLE_SOURCES = Arrays.stream(VulnSource.values())
            .filter(VulnSource::isPushable)
            .filter(source -> Objects.equals(source.category, VulnSourceCategory.PUBLIC)
                    || Objects.equals(source.category, VulnSourceCategory.PRIVATE)
                    || Objects.equals(VulnSource.UVP_ALL, source))
            .toList();

    public static List<VulnSource> getPublicSources() {
        return PUBLIC_SOURCES;
    }

    public static List<VulnSource> getPublicOrUnpushablePrivateSources() {
        return PUBLIC_OR_UNPUSHABLE_PRIVATE_SOURCES;
    }

    public static List<VulnSource> getPushableSources() {
        return PUSHABLE_SOURCES;
    }

    public static List<VulnSource> getUnpushableSources() {
        return UNPUSHABLE_SOURCES;
    }

    public VulnSourceCategory getCategory() {
        return category;
    }

    public boolean isPushable() {
        return pushable;
    }

    public boolean isPublicPushable() {
        return PUBLIC_PUSHABLE_SOURCES.contains(this);
    }

    public boolean isPrivatePushable() {
        return PRIVATE_PUSHABLE_SOURCES.contains(this);
    }

    public VulnSource unifyPushSource() {
        return Objects.equals(VulnSource.UVP_ALL, this) ? VulnSource.UVP : this;
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
