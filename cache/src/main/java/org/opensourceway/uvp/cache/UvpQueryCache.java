package org.opensourceway.uvp.cache;

import org.opensourceway.uvp.cache.config.CacheProperties;
import org.opensourceway.uvp.constant.CacheConstant;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UvpQueryCache {
    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties<?, ?> uvpQueryCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstant.UVP_QUERY_CACHE)
                .maximumCacheSize(1000L)
                // 5 minutes.
                .expireAfterWrite(5 * 60L)
                .cacheNullValue(true)
                .build();
    }
}
