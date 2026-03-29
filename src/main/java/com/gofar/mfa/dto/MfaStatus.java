package com.gofar.mfa.dto;


import lombok.Builder;

@Builder
public record MfaStatus (
        boolean mfaEnabled,
        boolean mfaVerified,
        String message
) {
}
