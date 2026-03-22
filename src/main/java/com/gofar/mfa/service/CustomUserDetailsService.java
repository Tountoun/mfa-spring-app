package com.gofar.mfa.service;

import com.gofar.mfa.entity.User;
import com.gofar.mfa.repository.UserRepository;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    @NonNull
    public UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        log.debug("Loading user details for username: {}", username);

        User user = this.userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("User not found with username: {}", username);
                    return new UsernameNotFoundException(String.format("User with username %s not found", username));
                });

        log.debug("User found: {}, Account locked: {}, Enabled: {}",
                  username, user.isAccountLocked(), user.isEnabled());

        List<GrantedAuthority> authorities = user.getRoles()
                .stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(authorities)
                .accountLocked(user.isAccountLocked())
                .disabled(!user.isEnabled())
                .build();
    }


    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}
