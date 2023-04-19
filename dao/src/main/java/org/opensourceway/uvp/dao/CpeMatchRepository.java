package org.opensourceway.uvp.dao;

import org.opensourceway.uvp.entity.CpeMatch;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface CpeMatchRepository extends JpaRepository<CpeMatch, UUID> {
}
