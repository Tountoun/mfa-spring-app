package com.gofar.mfa.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
@Schema(name = "MfaSetupData", description = "Data transfer object for MFA setup")
public class MfaSetupData {
    @Schema(description = "Secret key for the TOTP", example = "12345678901234567890123456789012")
    private String secret;
    @Schema(description = "OTP Auth URL for the TOTP", example = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30")
    private String otpAuthUrl;
    @Schema(description = "QR code base64 for the TOTP", example = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAAEsCAYAAAA8IYyKAAAgAElEQVR4Aey")
    private String qrCodeBase64;
    @Schema(description = "Scratch codes for the TOTP", example = "[\"12345678\", \"87654321\", \"135792468\"]")
    private List<String> scratchCodes;
}
