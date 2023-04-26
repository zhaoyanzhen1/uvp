package org.opensourceway.uvp.batch.chunk.reader.dumper;

import org.opensourceway.uvp.clients.Vtopia;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public class VtopiaReader implements ItemReader<Integer> {

    private static final Logger logger = LoggerFactory.getLogger(VtopiaReader.class);

    @Value("${vtopia.api.page_size}")
    private Integer pageSize;

    @Autowired
    private Vtopia vtopia;

    private AtomicInteger page = null;

    private AtomicInteger totalPage = new AtomicInteger(Integer.MIN_VALUE);

    @Override
    public Integer read() {
        if (totalPage.get() == Integer.MIN_VALUE) {
            synchronized (this) {
                initMapper();
            }
        }

        // Failed to get totalPage, pass Integer.MIN_VALUE to processor to retry.
        if (totalPage.get() == Integer.MIN_VALUE) {
            return Integer.MIN_VALUE;
        }

        // End of loop.
        if (totalPage.get() < page.get()) {
            return null;
        }

        return page.addAndGet(1);
    }

    private void initMapper() {
        if (totalPage.get() != Integer.MIN_VALUE) {
            return;
        }

        logger.info("Query Vtopia CVE total size");

        var resp = vtopia.dumpCves(0, 0);
        // Maybe some failure occur, try to call Vtopia API next time.
        if (Objects.isNull(resp)) {
            logger.warn("Get null response from Vtopia.");
            return;
        }

        totalPage = new AtomicInteger((int) Math.ceil(resp.body().total().doubleValue() / pageSize));
        page = new AtomicInteger(0);
        logger.info("Number of Vtopia CVE: <{}>.", resp.body().total());
    }
}
