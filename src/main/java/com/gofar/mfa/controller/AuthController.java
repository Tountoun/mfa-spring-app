package com.gofar.mfa.controller;

import com.gofar.mfa.dto.ApiResponse;
import com.gofar.mfa.dto.AuthDto;
import com.gofar.mfa.dto.MfaEnableRequest;
import com.gofar.mfa.dto.MfaSetupData;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
            // MFA already enabled
            return ResponseEntity.badRequest().body(null);
        }

        MfaSetupData setupData = this.tOtpService.setupMfa(user);

        return ResponseEntity.ok(ApiResponse.ok("MFA setup initialized", setupData));
    }


    @PostMapping("/mfa/enable")
    @Operation(summary = "Enable MFA", description = "Enable MFA for the authenticated user (Confirmation after QR Code scan)")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse> enableMfa(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody MfaEnableRequest request
    ) {
        User user = getAuthenticatedUser(userDetails.getUsername());

        if (this.tOtpService.enableMfa(user, request.totp())) {
            return ResponseEntity.ok(ApiResponse.ok("MFA enabled successfully. Keep your scratch codes safe."));
        }

        return ResponseEntity.badRequest().body(ApiResponse.error("Invalid TOTP. Check your device and try again."));
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
