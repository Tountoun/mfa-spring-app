package com.gofar.mfa.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MfaEnableRequest(
        @NotBlank
        @Size(min = 6, max = 6, message = "TOTP must be 6 characters long")
        @Schema(description = "TOTP code", example = "123456")
        String totp
) {
}
