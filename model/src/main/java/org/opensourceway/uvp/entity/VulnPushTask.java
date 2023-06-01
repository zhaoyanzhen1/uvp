package org.opensourceway.uvp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.opensourceway.uvp.enums.PushType;

import java.sql.Timestamp;
import java.util.UUID;

/**
 * Describes the push tasks of a vulnerability.
 */
@Entity
@Table(indexes = {
        @Index(name = "vuln_push_task_uk", columnList = "vuln_id, subscriber_id, created", unique = true)
})
public class VulnPushTask {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Push type of vulnerability.
     */
    @Convert(converter = PushType.PushTypeConverter.class)
    @Column(columnDefinition = "TEXT", nullable = false)
    private PushType type;

    /**
     * The time when this tuple is created.
     */
    @Column(columnDefinition = "TIMESTAMP WITH TIME ZONE", nullable = false)
    @CreationTimestamp
    private Timestamp created;

    /**
     * The last time when a vulnerability is pushed to a subscriber.
     */
    @Column(columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private Timestamp lastPushed;

    /**
     * The time when a vulnerability is SUCCESSFULLY pushed to a subscriber.
     * <p>
     * The value SHOULD be null if not SUCCESSFULLY pushed.
     */
    @Column(columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private Timestamp successfullyPushed;

    /**
     * The number of times a vulnerability is pushed to a subscriber.
     */
    @Column
    private Integer pushCount = 0;

    @Column(columnDefinition = "TEXT")
    private String errorMessage;

    /**
     * The subscriber to whom a vulnerability is pushed.
     */
    @ManyToOne
    @JoinColumn(name = "subscriber_id", foreignKey = @ForeignKey(name = "subscriber_id_fk"))
    private Subscriber subscriber;

    /**
     * The vulnerability to be/was pushed.
     */
    @ManyToOne
    @JoinColumn(name = "vuln_id", foreignKey = @ForeignKey(name = "vuln_id_fk"))
    private Vulnerability vulnerability;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public PushType getType() {
        return type;
    }

    public void setType(PushType type) {
        this.type = type;
    }

    public Timestamp getCreated() {
        return created;
    }

    public void setCreated(Timestamp created) {
        this.created = created;
    }

    public Timestamp getLastPushed() {
        return lastPushed;
    }

    public void setLastPushed(Timestamp lastPushed) {
        this.lastPushed = lastPushed;
    }

    public Timestamp getSuccessfullyPushed() {
        return successfullyPushed;
    }

    public void setSuccessfullyPushed(Timestamp successfullyPushed) {
        this.successfullyPushed = successfullyPushed;
    }

    public Integer getPushCount() {
        return pushCount;
    }

    public void setPushCount(Integer pushCount) {
        this.pushCount = pushCount;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public Subscriber getSubscriber() {
        return subscriber;
    }

    public void setSubscriber(Subscriber subscriber) {
        this.subscriber = subscriber;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }
}
