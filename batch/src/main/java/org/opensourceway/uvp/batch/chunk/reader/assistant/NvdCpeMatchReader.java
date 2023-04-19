package org.opensourceway.uvp.batch.chunk.reader.assistant;

import org.opensourceway.uvp.clients.Nvd;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public class NvdCpeMatchReader implements ItemReader<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(NvdCpeMatchReader.class);

    @Value("${nvd.api.cpematch.page_size}")
    private Integer nvdCpeMatchPageSize;

    @Autowired
    private Nvd nvd;

    private AtomicInteger startIndex = null;

    private AtomicInteger totalResults = new AtomicInteger(Integer.MIN_VALUE);

    @Override
    public Integer read() {
        if (totalResults.get() == Integer.MIN_VALUE) {
            synchronized (this) {
                initMapper();
            }
        }

        // Failed to get totalResults, pass Integer.MIN_VALUE to processor to retry.
        if (totalResults.get() == Integer.MIN_VALUE) {
            return Integer.MIN_VALUE;
        }

        // End of loop.
        if (totalResults.get() <= startIndex.get()) {
            return null;
        }

        return startIndex.addAndGet(nvdCpeMatchPageSize);
    }

    private void initMapper() {
        if (totalResults.get() != Integer.MIN_VALUE) {
            return;
        }

        logger.info("Query NVD CPE match total size");

        var resp = nvd.dumpCpes(0);
        // Maybe some failure occur, try to call NVD API next time.
        if (Objects.isNull(resp)) {
            logger.warn("Get null response from NVD.");
            return;
        }

        totalResults = new AtomicInteger(resp.getTotalResults());
        startIndex = new AtomicInteger(-nvdCpeMatchPageSize);
        logger.info("Number of NVD CPE match: <{}>.", totalResults);
    }
}
