package org.opensourceway.uvp.batch.chunk.processor.assistant;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.clients.Nvd;
import org.opensourceway.uvp.entity.CpeMatch;
import org.opensourceway.uvp.pojo.nvd.cpematch.MatchCpe;
import org.opensourceway.uvp.pojo.nvd.cpematch.MatchString;
import org.opensourceway.uvp.pojo.nvd.cpematch.MatchStringStatus;
import org.opensourceway.uvp.pojo.nvd.cpematch.MatchStringWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ObjectUtils;

import java.util.List;
import java.util.Objects;

public class NvdCpeMatchProcessor implements ItemProcessor<Integer, List<CpeMatch>> {

    private static final Logger logger = LoggerFactory.getLogger(NvdCpeMatchProcessor.class);

    @Autowired
    private Nvd nvd;

    @Override
    public List<CpeMatch> process(@NotNull Integer startIndex) throws Exception {
        logger.info("Start to get NVD CPE match with startIndex: <{}>.", startIndex);

        if (startIndex == Integer.MIN_VALUE) {
            return null;
        }

        var resp = nvd.dumpCpes(startIndex);
        // Maybe some failure occur, try to call NVD API next time.
        if (Objects.isNull(resp)) {
            logger.warn("Get null response from NVD.");
            throw new RuntimeException("Get null response from NVD.");
        }

        try {
            var cpeMatches = resp.getMatchStrings()
                    .stream()
                    .map(MatchStringWrapper::matchString)
                    .map(this::toCpeMatch)
                    .filter(Objects::nonNull)
                    .toList();

            logger.info("End to process NVD CPE match.");
            return cpeMatches;
        } catch (Exception e) {
            logger.warn("Exception occurs when process NVD CPE match.", e);
            throw new RuntimeException(e);
        }
    }

    private CpeMatch toCpeMatch(MatchString matchString) {
        if (!MatchStringStatus.ACTIVE.equals(matchString.status())) {
            return null;
        }

        if (ObjectUtils.isEmpty(matchString.matches())) {
            return null;
        }

        var cpeMatch = new CpeMatch();
        cpeMatch.setMatchCriteriaId(matchString.matchCriteriaId());
        cpeMatch.setCpes(matchString.matches().stream().map(MatchCpe::cpeName).toList());
        return cpeMatch;
    }
}
