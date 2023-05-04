package org.opensourceway.uvp.utility;

import java.util.regex.Pattern;

public class RegexUtil {
    public static boolean isCveId(String vulnId) {
        return Pattern.compile("(cve|CVE)-[0-9]{4}-[0-9]{4,}$").matcher(vulnId).matches();
    }
}
