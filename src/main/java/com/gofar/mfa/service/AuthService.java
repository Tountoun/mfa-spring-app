package com.gofar.mfa.service;


import com.gofar.mfa.dto.AuthDto;
import com.gofar.mfa.dto.MfaVerifyRequest;
import com.gofar.mfa.entity.User;
import com.gofar.mfa.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final TOtpService tOtpService;

    @Value("${app.security.max-login-attempts:5}")
    private int maxLoginAttempts;

    @Value("${app.security.lockout-duration-minutes:15}")
    private int lockoutDurationMinutes;


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
     * This method is used to authenticate a user and issue a JWT token if credentials are valid
     * @param loginRequest the login request
     * @return the login response with token and user info
     */
    public AuthDto.LoginResponse authenticate(AuthDto.LoginRequest loginRequest) {
        User user = this.userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> {
                    log.warn("Authentication failed: User not found with username: {}", loginRequest.getUsername());
                    return new BadCredentialsException("Invalid user credentials");
                });

        checkAccountLock(user);

        try {
            this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );
        } catch (AuthenticationException e) {
            log.warn("Authentication failed: Invalid credentials for user: {}", user.getUsername());
            handleFailedAuthentication(user);
            throw new BadCredentialsException("Invalid user credentials");
        }

        userRepository.resetFailedAttempts(user.getUsername());
        userRepository.updateLastLogin(user.getUsername(), LocalDateTime.now());

        if (user.isMfaEnabled()) {
            String preAuthToken = this.jwtService.generatePreAuthToken(user.getUsername());
            log.info("Login succeeded. MFA required for user {}", user.getUsername());
            return AuthDto.LoginResponse.mfaRequired(preAuthToken, getUserInfoAfterRegistration(user));
        }
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(user.getUsername());
        String token = jwtService.generateToken(userDetails);
        log.info("Authentication successful for user: {}", user.getUsername());
        return AuthDto.LoginResponse.success(token, getUserInfoAfterRegistration(user));
    }

    /**
     * This method is used to authenticate a user with MFA and issue a JWT token if credentials are valid
     * @param request the MFA verification request
     * @return the login response with token and user info
     */
    public AuthDto.LoginResponse authenticateWithMfa(MfaVerifyRequest request) {
        String username = this.jwtService.extractUsername(request.preAuthToken());
        if (!this.jwtService.isPreAuthTokenValid(request.preAuthToken(), username)) {
            throw new BadCredentialsException("Invalid or expired pre-authentication token");
        }
        User user = this.userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("Authentication failed: User not found with username: {}", username);
                    return new BadCredentialsException("Invalid user credentials");
                });

        if (!user.isMfaEnabled()) {
            throw new IllegalStateException("MFA is not enabled for user: " + user.getUsername());
        }

        if (!this.tOtpService.verifyTotp(user.getMfaSecret(), request.code())) {
            handleFailedAuthentication(user);
            throw new IllegalArgumentException("Invalid MFA code. Please try again.");
        }

        this.userRepository.resetFailedAttempts(user.getUsername());
        log.info("MFA verified for user: {}", user.getUsername());
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(user.getUsername());
        String token = jwtService.generateToken(userDetails);
        return AuthDto.LoginResponse.success(token, getUserInfoAfterRegistration(user));
    }

    /**
     * Handle failed authentication
     * This method is called when the authentication fails,
     * It updates the failed attempts and locks the account if the max attempts are reached
     * @param user the user entity
     */
    private void handleFailedAuthentication(User user) {
        int currentTotalAttempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(currentTotalAttempts);

        log.debug("Failed login attempt {} for user: {}", currentTotalAttempts, user.getUsername());

        if (currentTotalAttempts >= this.maxLoginAttempts) {
            user.setAccountLocked(true);
            user.setLockTime(LocalDateTime.now());
            log.warn("Account locked for user: {} after {} failed attempts", user.getUsername(), currentTotalAttempts);
        }

        this.userRepository.updateLoginAttempts(
                user.getUsername(),
                currentTotalAttempts,
                user.getLockTime(),
                user.isAccountLocked()
        );
    }

    /**
     * Check if the account is locked and unlock it if the lockout duration is over
     * @param user the user entity
     */
    private void checkAccountLock(User user) {
        if (user.isAccountLocked()) {
            if (Objects.nonNull(user.getLockTime()) && LocalDateTime.now().isAfter(user.getLockTime().plusMinutes(this.lockoutDurationMinutes))) {
                this.userRepository.resetFailedAttempts(user.getUsername());
                return;
            }
            log.warn("Account is locked for user: {}", user.getUsername());
            int remainingMinutes = Math.toIntExact(this.lockoutDurationMinutes - Duration.between(user.getLockTime(), LocalDateTime.now()).toMinutes());
            throw new LockedException("Account is locked. Please retry after " + remainingMinutes + " minutes.");
        }
    }

    /**
     * Get the user info after registration
     * @param user the user entity
     * @return the necessary user details
     */
    public AuthDto.UserInfo getUserInfoAfterRegistration(User user) {
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

    @Autowired
    public void setJwtService(JwtService jwtService) {
        this.jwtService = jwtService;
    }
}
