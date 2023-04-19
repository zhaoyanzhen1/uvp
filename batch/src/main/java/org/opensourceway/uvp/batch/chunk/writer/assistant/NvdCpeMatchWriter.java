package org.opensourceway.uvp.batch.chunk.writer.assistant;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.dao.CpeMatchRepository;
import org.opensourceway.uvp.entity.CpeMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.Chunk;
import org.springframework.batch.item.ItemWriter;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class NvdCpeMatchWriter implements ItemWriter<List<CpeMatch>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(NvdCpeMatchWriter.class);

    @Autowired
    private CpeMatchRepository cpeMatchRepository;

    @Override
    public void write(Chunk<? extends List<CpeMatch>> chunk) {
        logger.info("Start to persist batch CPE matches.");
        var cpeMatches = chunk.getItems().stream().flatMap(List::stream).distinct().toList();
        cpeMatchRepository.saveAll(cpeMatches);
        logger.info("End to persist batch <{}> CPE matches.", cpeMatches.size());
    }

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        logger.info("Delete all existing CPE matches in database.");
        cpeMatchRepository.deleteAll();
    }
}
