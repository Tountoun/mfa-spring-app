package com.gofar.mfa.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class User extends BaseAuditing {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(unique = true, nullable = false, length = 50)
    private String username;
    @Column(unique = true, nullable = false, length = 100)
    private String email;
    @Column(length = 100)
    private String firstName;
    @Column(length = 100)
    private String lastName;
    @Column(nullable = false)
    private String password;

    @Column(nullable = false, name = "mfa_enabled")
    @Builder.Default
    private boolean mfaEnabled = false;
    @Column(name = "mfa_secret")
    private String mfaSecret;
    @Column(name = "mfa_verified", nullable = false)
    @Builder.Default
    private boolean mfaVerified = false;
    @Column(name = "scratch_codes", length = 500)
    private String scratchCodes;

    @Column(name = "account_locked", nullable = false)
    @Builder.Default
    private boolean accountLocked = false;
    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private int failedAttempts = 0;
    @Column(name = "lock_time")
    private LocalDateTime lockTime;
    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private boolean enabled = true;
    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    @Builder.Default
    private Set<String> roles = new HashSet<>();
}
