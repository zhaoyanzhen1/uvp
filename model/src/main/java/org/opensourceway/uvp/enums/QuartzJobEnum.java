package org.opensourceway.uvp.enums;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Objects;

public enum QuartzJobEnum {
    DUMP_VULN_JOB("0 0 2 * * ? *"),

    CAPTURE_CRON_JOB("*/10 * * * * ? *"),
    ;

    private final String defaultCron;

    QuartzJobEnum(String defaultCron) {
        this.defaultCron = defaultCron;
    }

    public String getDefaultCron() {
        return defaultCron;
    }

    @Converter(autoApply = true)
    public static class QuartzJobConverter implements AttributeConverter<QuartzJobEnum, String> {

        @Override
        public String convertToDatabaseColumn(QuartzJobEnum quartzJobEnum) {
            return Objects.nonNull(quartzJobEnum) ? quartzJobEnum.name() : null;
        }

        @Override
        public QuartzJobEnum convertToEntityAttribute(String dbData) {
            if (Objects.isNull(dbData)) {
                return null;
            }
            return QuartzJobEnum.valueOf(dbData);
        }
    }
}
