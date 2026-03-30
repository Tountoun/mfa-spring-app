package com.gofar.mfa.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "MfaVerifyRequest", description = "Data transfer object for MFA verification")
public record MfaVerifyRequest(
        @NotBlank
        @Schema(description = "Pre-authentication token", example = "123e4567-e89b-12d3-a456-426614174000")
        String preAuthToken,
        @NotBlank
        @Size(min = 6, max = 6, message = "Code must be 6 characters long")
        @Schema(description = "TOTP code or scratch code", example = "123456")
        String code
) {
}
