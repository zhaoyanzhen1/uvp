package org.opensourceway.uvp.pojo.request;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import org.opensourceway.uvp.constant.UvpConstant;
import org.springframework.data.domain.AbstractPageRequest;

import java.util.Objects;

public class SearchRequest {
    /**
     * Search keyword, may be a PURL/package name/vulnerability id.
     */
    private String keyword = "";

    /**
     * @See {@link AbstractPageRequest#getPageNumber()}
     */
    @Min(0)
    private Integer page = 0;

    /**
     * @See {@link AbstractPageRequest#getPageSize()}
     */
    @Size(min = 1, max = UvpConstant.SEARCH_PAGE_SIZE_LIMIT)
    private Integer size = UvpConstant.SEARCH_PAGE_SIZE_DEFAULT;

    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword;
    }

    public Integer getPage() {
        return page;
    }

    public void setPage(Integer page) {
        this.page = page;
    }

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    @Override
    public String toString() {
        return "SearchRequest{" +
                "keyword='" + keyword + '\'' +
                ", page=" + page +
                ", size=" + size +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SearchRequest that = (SearchRequest) o;
        return Objects.equals(keyword, that.keyword)
                && Objects.equals(page, that.page)
                && Objects.equals(size, that.size);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyword, page, size);
    }
}
