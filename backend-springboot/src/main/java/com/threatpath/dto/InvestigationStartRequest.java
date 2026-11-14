package com.threatpath.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class InvestigationStartRequest {
    @NotBlank(message = "Investigation objective must not be empty.")
    @Size(min = 10, max = 1000, message = "Objective must be between 10 and 1000 characters.")
    private String objective;

    public String getObjective() { return objective; }
    public void setObjective(String objective) { this.objective = objective; }
}
