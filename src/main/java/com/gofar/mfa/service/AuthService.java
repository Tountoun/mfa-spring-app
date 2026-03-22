package com.gofar.mfa.service;


import com.gofar.mfa.dto.AuthDto;
import com.gofar.mfa.entity.User;
import com.gofar.mfa.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Slf4j
@Service
public class AuthService {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;


    /**
     * Register a new user
     * @param registrationData the data to register the user
     */
    @Transactional
    public AuthDto.UserInfo register(AuthDto.RegistrationDto registrationData) {
        log.info("Attempting to register new user with username: {}", registrationData.getUsername());

        if (this.userRepository.existsByUsername(registrationData.getUsername())) {
            log.warn("Registration failed: Username '{}' already exists", registrationData.getUsername());
            throw new IllegalArgumentException("Username already exists");
        }
        if (this.userRepository.existsByEmail(registrationData.getEmail())) {
            log.warn("Registration failed: Email '{}' already exists", registrationData.getEmail());
            throw new IllegalArgumentException("Email already exists");
        }

        User user = getUserDataForRegistration(registrationData);
        this.userRepository.save(user);
        log.info("Successfully registered user: {} with email: {}", user.getUsername(), user.getEmail());

        return getUserInfoAfterRegistration(user);
    }

    /**
     * Get the user info after registration
     * @param user the user entity
     * @return the necessary user details
     */
    private AuthDto.UserInfo getUserInfoAfterRegistration(User user) {
        return AuthDto.UserInfo.builder()
                .id(user.getId())
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .mfaEnabled(user.isMfaEnabled())
                .roles(user.getRoles())
                .lastLogin(user.getLastLogin())
                .build();
    }

    /**
     * Map the registration data to the user entity
     * @param registrationData the data to register the user
     * @return the user entity
     */
    private User getUserDataForRegistration(AuthDto.RegistrationDto registrationData) {
        return User.builder()
                .username(registrationData.getUsername())
                .email(registrationData.getEmail())
                .firstName(registrationData.getFirstName())
                .lastName(registrationData.getLastName())
                .roles(Set.of("ROLE_USER"))
                .password(this.passwordEncoder.encode(registrationData.getPassword()))
                .build();
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
}
