package org.opensourceway.uvp.service;

import org.opensourceway.uvp.constant.CacheConstant;
import org.opensourceway.uvp.constant.UvpConstant;
import org.opensourceway.uvp.dao.PackageRepository;
import org.opensourceway.uvp.entity.Package;
import org.opensourceway.uvp.pojo.osv.OsvVulnerability;
import org.opensourceway.uvp.pojo.request.SearchRequest;
import org.opensourceway.uvp.pojo.response.PackageVulns;
import org.opensourceway.uvp.pojo.response.SearchResp;
import org.opensourceway.uvp.pojo.response.VulnDetailResp;
import org.opensourceway.uvp.utility.OsvEntityHelper;
import org.opensourceway.uvp.utility.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional(rollbackFor = Exception.class)
public class UvpServiceImpl implements UvpService {
    private static final Logger logger = LoggerFactory.getLogger(UvpServiceImpl.class);

    @Autowired
    private VulnLocalService vulnLocalService;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private OsvEntityHelper osvEntityHelper;

    @Override
    @Cacheable(value = {CacheConstant.UVP_QUERY_CACHE})
    public List<OsvVulnerability> query(String purl) {
        PurlUtil.validate(purl);

        return vulnLocalService.query(purl).stream().map(osvEntityHelper::toVo).toList();
    }

    @Override
    public List<PackageVulns> queryBatch(List<String> purls) {
        purls = purls.stream().distinct().toList();
        PurlUtil.validate(purls);

        return vulnLocalService.queryBatch(purls).entrySet()
                .stream()
                .map(entry -> new PackageVulns(entry.getKey(), entry.getValue()
                        .stream().map(osvEntityHelper::toVo).toList()))
                .toList();
    }

    @Override
    public void importBatch(List<String> purls) {
        purls = purls.stream().distinct().collect(Collectors.toList());
        PurlUtil.validate(purls);

        packageRepository.lockTable();

        purls.removeAll(packageRepository.findAll().stream().map(Package::getPurl).toList());
        packageRepository.saveAll(purls.stream().map(PurlUtil::purlToPackage).toList());
    }

    @Override
    @Cacheable(value = {CacheConstant.UVP_SEARCH_CACHE})
    public SearchResp search(SearchRequest request) {
        if (request.getPage() < 0) {
            throw new IllegalArgumentException("Page index must not be less than zero");
        }

        if (request.getSize() < 1) {
            throw new IllegalArgumentException("Page size must not be less than one");
        }

        if (request.getSize() > UvpConstant.SEARCH_PAGE_SIZE_LIMIT) {
            throw new IllegalArgumentException("Page size must not be greater than %s".formatted(
                    UvpConstant.SEARCH_PAGE_SIZE_LIMIT));
        }

        // Get one more tuple to check if last page is reached.
        var vulns = vulnLocalService.search(request.getKeyword(), request.getSize() + 1,
                request.getPage() * request.getSize());
        var resp = new SearchResp();
        resp.setVulns(vulns.subList(0, vulns.size() > request.getSize() ? request.getSize() : vulns.size())
                .stream().map(osvEntityHelper::toSearchObj).toList());
        resp.setLastPage(vulns.size() <= request.getSize());
        return resp;
    }

    @Override
    public VulnDetailResp queryVulnDetail(String vulnId) {
        return osvEntityHelper.toDetail(vulnLocalService.queryVulnDetail(vulnId));
    }
}
