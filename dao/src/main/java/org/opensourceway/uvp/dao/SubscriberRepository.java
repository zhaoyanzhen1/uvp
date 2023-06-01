package org.opensourceway.uvp.dao;

import org.opensourceway.uvp.entity.Subscriber;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SubscriberRepository extends JpaRepository<Subscriber, UUID> {
    List<Subscriber> findByActive(Boolean active);
}