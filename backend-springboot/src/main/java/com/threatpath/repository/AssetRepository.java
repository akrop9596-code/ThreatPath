package com.threatpath.repository;

import com.threatpath.entity.AssetEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface AssetRepository extends JpaRepository<AssetEntity, Long> {
    Optional<AssetEntity> findByIpAddress(String ipAddress);
    Optional<AssetEntity> findByAssetCode(String assetCode);
}
