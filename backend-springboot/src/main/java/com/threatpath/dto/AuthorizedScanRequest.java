package com.threatpath.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class AuthorizedScanRequest {
    @NotBlank(message = "Scan target is required.")
    @Pattern(regexp = "^[0-9./]+$", message = "Target must be a valid IPv4 address or CIDR block without shell characters.")
    private String target;

    @NotBlank(message = "Scan profile is required.")
    private String profile = "quick_safe";

    private Boolean humanApprovedForActiveScan = true;

    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }
    public String getProfile() { return profile; }
    public void setProfile(String profile) { this.profile = profile; }
    public Boolean getHumanApprovedForActiveScan() { return humanApprovedForActiveScan; }
    public void setHumanApprovedForActiveScan(Boolean humanApprovedForActiveScan) { this.humanApprovedForActiveScan = humanApprovedForActiveScan; }
}
