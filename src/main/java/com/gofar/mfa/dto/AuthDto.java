package com.gofar.mfa.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

public class AuthDto {

    @Data
    public static class RegistrationDto {
        @NotBlank(message = "The username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters long")
        private String username;

        private String firstName;
        private String lastName;

        @NotBlank(message = "The email is required")
        @Email(message = "Invalid email address")
        private String email;

        @NotBlank(message = "The password is required")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        private String password;
    }

    @Data
    @Builder
    public static class UserInfo {
        private UUID id;
        private String username;
        private String firstName;
        private String lastName;
        private String email;
        private boolean mfaEnabled;
        private Set<String> roles;
        private LocalDateTime lastLogin;
    }
}
