package com.gofar.mfa.dto;

import io.swagger.v3.oas.annotations.media.Schema;
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
    @Schema(name = "RegistrationDto", description = "Data transfer object for user registration")
    public static class RegistrationDto {
        @NotBlank(message = "The username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters long")
        @Schema(description = "Username for login purpose", example = "johndoe")
        private String username;

        @Schema(description = "First name of the user", example = "John")
        private String firstName;
        @Schema(description = "Last name of the user", example = "Doe")
        private String lastName;

        @NotBlank(message = "The email is required")
        @Email(message = "Invalid email address")
        @Schema(description = "Email address of the user", example = "john.doe@example.com")
        private String email;

        @NotBlank(message = "The password is required")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        @Schema(description = "The password of user for login purpose", example = "password123")
        private String password;
    }

    @Data
    @Schema(name = "LoginRequest", description = "Data transfer object for user login")
    public static class LoginRequest {
        @NotBlank(message = "The username is required")
        @Schema(description = "Username for login purpose", example = "johndoe")
        private String username;

        @NotBlank(message = "The password is required")
        @Schema(description = "The password of user for login purpose", example = "password123")
        private String password;
    }

    @Data
    @Schema(name = "LoginResponse", description = "Data transfer object for user login response")
    public static class LoginResponse {
        @Schema(description = "Is MFA required", example = "false")
        private boolean mfaRequired;

        @Schema(description = "Pre-authentication token in case MFA is required (short lived token)", example = "123e4567-e89b-12d3-a456-426614174000")
        private String preAuthToken;

        @Schema(description = "Access token in case MFA is not required", example = "123e4567-e89b-12d3-a456-426614174000")
        private String accessToken;

        @Schema(description = "Token type", example = "Bearer")
        private String tokenType = "Bearer";

        @Schema(description = "User information", implementation = UserInfo.class)
        private UserInfo user;

        public static LoginResponse success(String accessToken, UserInfo user) {
            LoginResponse r = new LoginResponse();
            r.mfaRequired = false;
            r.accessToken = accessToken;
            r.user = user;
            return r;
        }

        public static LoginResponse mfaRequired(String preAuthToken, UserInfo user) {
            LoginResponse r = new LoginResponse();
            r.mfaRequired = true;
            r.preAuthToken = preAuthToken;
            r.user = user;
            return r;
        }
    }

    @Data
    @Builder
    @Schema(name = "UserInfo", description = "Data transfer object for user information")
    public static class UserInfo {
        @Schema(description = "User ID", example = "123e4567-e89b-12d3-a456-426614174000")
        private UUID id;
        @Schema(description = "Username", example = "johndoe")
        private String username;
        @Schema(description = "First name", example = "John")
        private String firstName;
        @Schema(description = "Last name", example = "Doe")
        private String lastName;
        @Schema(description = "Email address", example = "john.doe@example.com")
        private String email;
        @Schema(description = "Is MFA enabled", example = "false")
        private boolean mfaEnabled;
        @Schema(description = "Roles", example = "[\"ROLE_USER\"]")
        private Set<String> roles;
        @Schema(description = "Last login date", example = "2021-01-01T00:00:00Z")
        private LocalDateTime lastLogin;
    }
}
