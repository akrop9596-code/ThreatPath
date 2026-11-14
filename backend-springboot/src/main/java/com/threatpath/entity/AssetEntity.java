package com.threatpath.entity;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;

@Entity
@Table(name = "assets")
public class AssetEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "asset_code", nullable = false, unique = true, length = 32)
    private String assetCode;

    @Column(nullable = false, length = 128)
    private String hostname;

    @Column(name = "ip_address", nullable = false, unique = true, length = 45)
    private String ipAddress;

    @Column(name = "subnet_cidr", nullable = false, length = 45)
    private String subnetCidr;

    @Column(name = "os_name", length = 128)
    private String osName;

    @Column(name = "asset_type", nullable = false, length = 32)
    private String assetType;

    @Column(name = "network_zone", nullable = false, length = 32)
    private String networkZone;

    @Column(name = "criticality_level", nullable = false, length = 16)
    private String criticalityLevel;

    @Column(name = "criticality_weight", nullable = false, precision = 4, scale = 2)
    private BigDecimal criticalityWeight;

    @Column(name = "is_authorized_target", nullable = false)
    private Boolean isAuthorizedTarget = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public String getAssetCode() { return assetCode; }
    public void setAssetCode(String assetCode) { this.assetCode = assetCode; }
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public String getSubnetCidr() { return subnetCidr; }
    public void setSubnetCidr(String subnetCidr) { this.subnetCidr = subnetCidr; }
    public String getOsName() { return osName; }
    public void setOsName(String osName) { this.osName = osName; }
    public String getAssetType() { return assetType; }
    public void setAssetType(String assetType) { this.assetType = assetType; }
    public String getNetworkZone() { return networkZone; }
    public void setNetworkZone(String networkZone) { this.networkZone = networkZone; }
    public String getCriticalityLevel() { return criticalityLevel; }
    public void setCriticalityLevel(String criticalityLevel) { this.criticalityLevel = criticalityLevel; }
    public BigDecimal getCriticalityWeight() { return criticalityWeight; }
    public void setCriticalityWeight(BigDecimal criticalityWeight) { this.criticalityWeight = criticalityWeight; }
    public Boolean getIsAuthorizedTarget() { return isAuthorizedTarget; }
    public void setIsAuthorizedTarget(Boolean isAuthorizedTarget) { this.isAuthorizedTarget = isAuthorizedTarget; }
    public Instant getCreatedAt() { return createdAt; }
}
