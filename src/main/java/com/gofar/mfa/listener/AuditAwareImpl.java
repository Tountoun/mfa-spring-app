package com.gofar.mfa.listener;

import lombok.NonNull;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.Optional;

@Component("auditAwareImpl")
public class AuditAwareImpl implements AuditorAware<String> {

    /**
     * Get the current auditor
     *
     * @return an optional of the current auditor name
     */
    @Override
    @NonNull
    public Optional getCurrentAuditor() {
        String user = "system";
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (Objects.nonNull(authentication) && !Objects.equals(authentication.getPrincipal(), "anonymousUser")) {
            user = authentication.getName();
        }
        return Optional.of(user);
    }
}
