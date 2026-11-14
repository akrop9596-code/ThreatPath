package com.threatpath.repository;

import com.threatpath.entity.AuditEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface AuditEventRepository extends JpaRepository<AuditEventEntity, Long> {
    List<AuditEventEntity> findTop50ByOrderByCreatedAtDesc();
}
