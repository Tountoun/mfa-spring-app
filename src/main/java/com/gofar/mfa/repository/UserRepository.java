package com.gofar.mfa.repository;

import com.gofar.mfa.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedAttempts = 0, u.lockTime = NULL, u.accountLocked = false WHERE u.username = :username")
    void resetFailedAttempts(@Param("username") String username);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedAttempts = :totalAttempts, u.lockTime = :lockTime, u.accountLocked = :accountLocked WHERE u.username = :username")
    void updateLoginAttempts(@Param("username") String username, @Param("totalAttempts") int currentTotalAttempts, @Param("lockTime") LocalDateTime lockTime, @Param("accountLocked") boolean accountLocked);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.lastLogin = :lastLogin WHERE u.username = :username")
    void updateLastLogin(@Param("username") String username, @Param("lastLogin") LocalDateTime localDateTime);
}
