package org.opensourceway.uvp.enums;

import com.fasterxml.jackson.annotation.JsonValue;
import com.github.packageurl.PackageURL;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * <a href="https://ossf.github.io/osv-schema/#affectedpackage-field">OSV-defined ecosystems</a>
 * <p/>
 * <a href="https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt">Ecosystems with zipped vulns at
 * https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip</a>
 */
public enum Ecosystem {
    UNKNOWN("Unknown", null, VersionType.ECOSYSTEM),

    ALPINE("Alpine", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_2("Alpine:v3.2", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_3("Alpine:v3.3", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_4("Alpine:v3.4", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_5("Alpine:v3.5", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_6("Alpine:v3.6", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_7("Alpine:v3.7", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_8("Alpine:v3.8", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_9("Alpine:v3.9", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_10("Alpine:v3.10", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_11("Alpine:v3.11", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_12("Alpine:v3.12", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_13("Alpine:v3.13", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_14("Alpine:v3.14", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_15("Alpine:v3.15", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_16("Alpine:v3.16", "apk", VersionType.ECOSYSTEM),

    ALPINE_3_17("Alpine:v3.17", "apk", VersionType.ECOSYSTEM),

    CRATES_IO("crates.io", PackageURL.StandardTypes.CARGO, VersionType.SEMVER),

    DEBIAN("Debian", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_3_0("Debian:3.0", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_3_1("Debian:3.1", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_4_0("Debian:4.0", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_5_0("Debian:5.0", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_6_0("Debian:6.0", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_7("Debian:7", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_8("Debian:8", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_9("Debian:9", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_10("Debian:10", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    DEBIAN_11("Debian:11", PackageURL.StandardTypes.DEBIAN, VersionType.ECOSYSTEM),

    GO("Go", PackageURL.StandardTypes.GOLANG, VersionType.SEMVER),

    HEX("Hex", PackageURL.StandardTypes.HEX, VersionType.SEMVER),

    MAVEN("Maven", PackageURL.StandardTypes.MAVEN, VersionType.ECOSYSTEM),

    NPM("npm", PackageURL.StandardTypes.NPM, VersionType.SEMVER),

    NUGET("NuGet", PackageURL.StandardTypes.NUGET, VersionType.ECOSYSTEM),

    OSS_FUZZ("OSS-Fuzz", PackageURL.StandardTypes.GENERIC, VersionType.ECOSYSTEM),

    PACKAGIST("Packagist", PackageURL.StandardTypes.COMPOSER, VersionType.ECOSYSTEM),

    PUB("Pub", "pub", VersionType.ECOSYSTEM),

    PYPI("PyPI", PackageURL.StandardTypes.PYPI, VersionType.ECOSYSTEM),

    RUBYGEMS("RubyGems", PackageURL.StandardTypes.GEM, VersionType.ECOSYSTEM),

    LINUX("Linux", null, VersionType.ECOSYSTEM),

    ANDROID("Android", null, VersionType.ECOSYSTEM),

    GITHUB_ACTIONS("GitHub Actions", null, VersionType.ECOSYSTEM),

    GSD("GSD", null, VersionType.ECOSYSTEM),

    UVI("UVI", null, VersionType.ECOSYSTEM),
    ;

    private final String ecosystem;

    private final String purlType;

    private final VersionType versionType;

    private static final Map<String, Ecosystem> ecosystemToEnum = Arrays.stream(Ecosystem.values())
            .collect(Collectors.toMap(Ecosystem::getEcosystem, Function.identity()));

    private static final Map<String, Ecosystem> purlTypeToEnum = Arrays.stream(Ecosystem.values())
            .filter(it -> Objects.nonNull(it.purlType)
                    && !StringUtils.equals(it.purlType, PackageURL.StandardTypes.GENERIC))
            // apk -> ALPINE, deb -> DEBIAN
            .collect(Collectors.toMap(Ecosystem::getPurlType, Function.identity(), (oldValue, value) -> oldValue));

    Ecosystem(String ecosystem, String purlType, VersionType versionType) {
        this.ecosystem = ecosystem;
        this.purlType = purlType;
        this.versionType = versionType;
    }

    @JsonValue
    public String getEcosystem() {
        return ecosystem;
    }

    public String getPurlType() {
        return purlType;
    }

    public VersionType getVersionType() {
        return versionType;
    }

    public static Ecosystem findByEcosystem(String ecosystem) {
        return ecosystemToEnum.get(ecosystem);
    }

    public static Ecosystem findByPurlType(String purlType) {
        return purlTypeToEnum.getOrDefault(purlType, UNKNOWN);
    }

    @Converter(autoApply = true)
    public static class EcosystemConverter implements AttributeConverter<Ecosystem, String> {

        @Override
        public String convertToDatabaseColumn(Ecosystem ecosystem) {
            return Objects.nonNull(ecosystem) ? ecosystem.ecosystem : null;
        }

        @Override
        public Ecosystem convertToEntityAttribute(String dbData) {
            if (Objects.isNull(dbData)) {
                return null;
            }
            return Optional.ofNullable(ecosystemToEnum.get(dbData))
                    .orElseThrow(() -> new IllegalArgumentException("Invalid ecosystem: %s".formatted(dbData)));
        }
    }
}
