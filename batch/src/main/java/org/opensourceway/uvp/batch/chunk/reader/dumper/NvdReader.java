package org.opensourceway.uvp.batch.chunk.reader.dumper;

import org.opensourceway.uvp.clients.Nvd;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public class NvdReader implements ItemReader<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(NvdReader.class);

    @Value("${nvd.api.cves.page_size}")
    private Integer nvdCvesPageSize;

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

        return startIndex.addAndGet(nvdCvesPageSize);
    }

    private void initMapper() {
        if (totalResults.get() != Integer.MIN_VALUE) {
            return;
        }

        logger.info("Query NVD CVE total size");

        var resp = nvd.dumpCves(0);
        // Maybe some failure occur, try to call NVD API next time.
        if (Objects.isNull(resp)) {
            logger.warn("Get null response from NVD.");
            return;
        }

        totalResults = new AtomicInteger(resp.getTotalResults());
        startIndex = new AtomicInteger(-nvdCvesPageSize);
        logger.info("Number of NVD CVE: <{}>.", totalResults);
    }
}
