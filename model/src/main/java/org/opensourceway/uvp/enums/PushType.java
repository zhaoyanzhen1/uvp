package org.opensourceway.uvp.enums;

import com.fasterxml.jackson.annotation.JsonValue;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum PushType {
    INSERT("insert"),

    UPDATE("update");

    private final String type;

    PushType(String type) {
        this.type = type;
    }

    @JsonValue
    public String getType() {
        return type;
    }

    private static final Map<String, PushType> valueToEnum = Arrays.stream(PushType.values())
            .collect(Collectors.toMap(PushType::getType, Function.identity()));


    @Converter(autoApply = true)
    public static class PushTypeConverter implements AttributeConverter<PushType, String> {

        @Override
        public String convertToDatabaseColumn(PushType type) {
            return Objects.nonNull(type) ? type.type : null;
        }

        @Override
        public PushType convertToEntityAttribute(String dbData) {
            if (Objects.isNull(dbData)) {
                return null;
            }
            return Optional.ofNullable(valueToEnum.get(dbData))
                    .orElseThrow(() -> new IllegalArgumentException("Invalid eventType: %s".formatted(dbData)));

        }
    }
}
