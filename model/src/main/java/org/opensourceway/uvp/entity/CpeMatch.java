package org.opensourceway.uvp.entity;

import com.vladmihalcea.hibernate.type.array.ListArrayType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import org.hibernate.annotations.Type;

import java.util.List;
import java.util.UUID;

/**
 * Active matchCriteriaId and corresponding cpes.
 *
 * @see <a href="https://nvd.nist.gov/developers/products">NVD CPE API DOC</a>
 */
@Entity
@Table(indexes = {
        @Index(name = "cpe_match_uk", columnList = "match_criteria_id", unique = true)
})
public class CpeMatch {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * MatchCriteriaId from NVD.
     */
    @Column(name = "match_criteria_id", columnDefinition = "TEXT", nullable = false)
    private String matchCriteriaId;

    /**
     * CPEs that matches the criteria id.
     */
    @Column(columnDefinition = "TEXT[]", nullable = false)
    @Type(ListArrayType.class)
    private List<String> cpes;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getMatchCriteriaId() {
        return matchCriteriaId;
    }

    public void setMatchCriteriaId(String matchCriteriaId) {
        this.matchCriteriaId = matchCriteriaId;
    }

    public List<String> getCpes() {
        return cpes;
    }

    public void setCpes(List<String> cpes) {
        this.cpes = cpes;
    }
}
