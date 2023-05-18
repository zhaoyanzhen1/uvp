package org.opensourceway.uvp.batch.chunk.reader.aggregator;

import org.apache.commons.collections4.ListUtils;
import org.opensourceway.uvp.dao.VulnerabilityRepository;
import org.opensourceway.uvp.enums.VulnSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

public class VulnAggregateReader implements ItemReader<List<String>> {

    private static final Logger logger = LoggerFactory.getLogger(VulnAggregateReader.class);

    private static final int BATCH_SIZE = 1000;

    private List<List<String>> vulnIdLists;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Override
    public List<String> read() {
        if (Objects.isNull(vulnIdLists)) {
            initMapper();
        }

        if (ObjectUtils.isEmpty(vulnIdLists)) {
            // end of loop
            return null;
        }

        return vulnIdLists.remove(0);
    }

    private void initMapper() {
        logger.info("Query distinct vulnerability IDs.");

        var vulnIds = vulnerabilityRepository.findDistinctUpsertUnpushableVulnIds(
                VulnSource.getUnpushableSources().stream().map(Enum::name).toList());
        vulnIdLists = ListUtils.partition(vulnIds, BATCH_SIZE)
                .stream()
                .map(ArrayList::new)
                .collect(Collectors.toCollection(CopyOnWriteArrayList::new));

        logger.info("Number of distinct vulnerability IDs: <{}>, chunks: <{}>.", vulnIds.size(), vulnIdLists.size());
    }
}
