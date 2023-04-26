package org.opensourceway.uvp.utility;

import org.opensourceway.uvp.enums.ScoringSystem;
import us.springett.cvss.Cvss;
import us.springett.cvss.CvssV3;

import java.util.Objects;
import java.util.Optional;

public class CvssUtil {
    public static Double calculateScore(String vector) {
        return Optional.ofNullable(Cvss.fromVector(vector)).map(it -> it.calculateScore().getBaseScore()).orElse(null);
    }

    public static ScoringSystem judgeScoringSystem(String vector) {
        if (Objects.isNull(Cvss.fromVector(vector))) {
            return null;
        }
        return Cvss.fromVector(vector) instanceof CvssV3 ? ScoringSystem.CVSS_V3 : ScoringSystem.CVSS_V2;
    }
}
