package com.gofar.mfa.controller;

import com.gofar.mfa.dto.*;
import com.gofar.mfa.entity.User;
import com.gofar.mfa.repository.UserRepository;
import com.gofar.mfa.service.AuthService;
import com.gofar.mfa.service.TOtpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Auth", description = "Authentication API")
public class AuthController {

    private AuthService authService;
    private TOtpService tOtpService;
    private UserRepository userRepository;


    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<ApiResponse> register(
            @Valid
            @RequestBody AuthDto.RegistrationDto registrationData
    ) {
        AuthDto.UserInfo userInfo = authService.register(registrationData);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok("User registered successfully", userInfo));
    }

    @PostMapping("/login")
    @Operation(summary = "Login a user", description = "Login a user and return a JWT token with user information")
    public ResponseEntity<ApiResponse> login(
            @Valid
            @RequestBody AuthDto.LoginRequest loginRequest
    ) {
        return ResponseEntity.ok(ApiResponse.ok("Login successful", this.authService.authenticate(loginRequest)));
    }

    @PostMapping("/mfa/setup")
    @Operation(summary = "Initialize MFA", description = "Initialize MFA setup for the authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> setupMfa(@AuthenticationPrincipal UserDetails userDetails) {
        User user = getAuthenticatedUser(userDetails.getUsername());
        if (user.isMfaEnabled()) {
            return ResponseEntity.badRequest().body(ApiResponse.error("Mfa already setup for user " + user.getUsername()));
        }

        MfaSetupData setupData = this.tOtpService.setupMfa(user);

        return ResponseEntity.ok(ApiResponse.ok("MFA setup initialized", setupData));
    }


    @PostMapping("/mfa/enable")
    @Operation(summary = "Enable MFA", description = "Enable MFA for the authenticated user (Confirmation after QR Code scan)")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> enableMfa(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody MfaOtpRequest request
    ) {
        User user = getAuthenticatedUser(userDetails.getUsername());

        if (this.tOtpService.enableMfa(user, request.totp())) {
            return ResponseEntity.ok(ApiResponse.ok("MFA enabled successfully. Keep your scratch codes safe."));
        }

        return ResponseEntity.badRequest().body(ApiResponse.error("Invalid TOTP. Check your device and try again."));
    }

    @PostMapping("/mfa/disable")
    @Operation(summary = "Disable MFA", description = "Disable MFA for the authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> disableMfa(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody MfaOtpRequest request
    ) {
        User user = getAuthenticatedUser(userDetails.getUsername());

        if (!this.tOtpService.disableMfa(user, request.totp())) {
            return ResponseEntity.badRequest().body(ApiResponse.error("MFA not disabled. Invalid TOTP; check your device and try again."));
        }
        return ResponseEntity.ok(ApiResponse.ok("MFA disabled successfully"));
    }

    @GetMapping("/mfa/status")
    @Operation(summary = "Get MFA status", description = "Get the MFA status for the authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> mfaStatus(@AuthenticationPrincipal UserDetails userDetails) {
        User user = getAuthenticatedUser(userDetails.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("Request executed successfully", MfaStatus.builder()
                .mfaEnabled(user.isMfaEnabled())
                .mfaVerified(user.isMfaVerified())
                .message(user.isMfaEnabled() ? "MFA is enabled. Your account is secure." : "MFA is not enabled. We recommend enabling it for better security.")
                .build()));
    }

    @GetMapping("/me")
    @Operation(summary = "Get authenticated user", description = "Get the authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> me(@AuthenticationPrincipal UserDetails userDetails) {
        User user = getAuthenticatedUser(userDetails.getUsername());

        return ResponseEntity.ok(ApiResponse.ok("Request executed successfully",
                this.authService.getUserInfoAfterRegistration(user)));
    }

    private User getAuthenticatedUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
    }

    @Autowired
    public void setAuthService(AuthService authService) {
        this.authService = authService;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Autowired
    public void settOtpService(TOtpService tOtpService) {
        this.tOtpService = tOtpService;
    }
}
