package org.opensourceway.uvp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.util.UUID;

/**
 * Describes a subscriber who should be notified of new or updated vulnerabilities.
 * <p>
 * In fact, this is an observer in observer pattern instead of a subscriber in pub-sub pattern
 * because there is no broker.
 */
@Entity
@Table(indexes = {
        @Index(name = "name_uk", columnList = "name", unique = true),
        @Index(name = "endpoint_uk", columnList = "endpoint", unique = true)
})
public class Subscriber {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Unique name of a subscriber.
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String name;

    /**
     * Endpoint of a subscriber.
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String endpoint;

    /**
     * Whether a subscriber actively subscribes to vulnerabilities.
     */
    @Column
    private Boolean active;

    /**
     * Whether vulnerabilities from private source are available for a subscriber.
     */
    @Column
    private Boolean privateAvailable;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public Boolean getPrivateAvailable() {
        return privateAvailable;
    }

    public void setPrivateAvailable(Boolean privateAvailable) {
        this.privateAvailable = privateAvailable;
    }
}
