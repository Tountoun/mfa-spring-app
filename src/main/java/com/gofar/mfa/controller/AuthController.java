package com.gofar.mfa.controller;

import com.gofar.mfa.dto.ApiResponse;
import com.gofar.mfa.dto.AuthDto;
import com.gofar.mfa.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Auth", description = "Authentication API")
public class AuthController {

    private AuthService authService;


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

    @Autowired
    public void setAuthService(AuthService authService) {
        this.authService = authService;
    }
}
