package com.gofar.mfa.controller;

import com.gofar.mfa.dto.ApiResponse;
import com.gofar.mfa.dto.AuthDto;
import com.gofar.mfa.service.AuthService;
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
public class AuthController {

    private AuthService authService;


    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(
            @Valid
            @RequestBody AuthDto.RegistrationDto registrationData
    ) {
        AuthDto.UserInfo userInfo = authService.register(registrationData);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok("User registered successfully", userInfo));
    }

    @Autowired
    public void setAuthService(AuthService authService) {
        this.authService = authService;
    }
}
