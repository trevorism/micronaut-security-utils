package com.trevorism.micronaut;

import com.trevorism.secure.Roles;
import com.trevorism.secure.Secure;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecuredAnnotationRule;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Singleton
@Replaces(SecuredAnnotationRule.class)
public class TrevorismSecurityRule implements SecurityRule {

    private static final Logger log = LoggerFactory.getLogger(TrevorismSecurityRule.class);
    @Override
    public int getOrder() {
        return -1000;
    }

    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, RouteMatch<?> routeMatch, Authentication authentication) {
        if (routeMatch instanceof MethodBasedRouteMatch methodBasedRouteMatch) {
            if (methodBasedRouteMatch.hasAnnotation(Secure.class)) {
                AnnotationValue<Secure> secureAnnotation = methodBasedRouteMatch.getAnnotation(Secure.class);
                if (validateClaims(secureAnnotation, authentication))
                    return Mono.just(SecurityRuleResult.ALLOWED);
                else
                    return Mono.just(SecurityRuleResult.REJECTED);
            }
        }
        return Mono.just(SecurityRuleResult.ALLOWED);

    }

    public boolean validateClaims(AnnotationValue<Secure> annotation, Authentication authentication) {
        try {
            validateInputs(annotation, authentication);
            validateIssuer(authentication);
            validateRole(annotation.stringValue(), annotation.booleanValue("allowInternal"), authentication.getRoles().stream().findFirst());
            return true;
        } catch (Exception e) {
            log.debug("Failed to validate claim: " + e.getMessage());
            return false;
        }
    }

    private void validateInputs(AnnotationValue<Secure> annotation, Authentication authentication) {
        if (authentication == null || authentication.getRoles().isEmpty()) {
            throw new RuntimeException("Unable to parse claim");
        }
        if (annotation == null) {
            throw new RuntimeException("Unable to validate against a method without the @Secure annotation");
        }
    }

    private void validateIssuer(Authentication authentication) {
        String issuer = authentication.getAttributes().get("iss").toString();
        if (!"https://trevorism.com".equals(issuer)) {
            throw new RuntimeException("Unexpected issuer: ${issuer}");
        }
    }

    private static void validateRole(Optional<String> role, Optional<Boolean> allowInternal, Optional<String> claimRole) {
        if (claimRole.isEmpty()) {
            throw new RuntimeException("Unable to parse claim role");
        }
        if (role.isEmpty()) {
            return;
        }
        String roleFromClaim = claimRole.get();
        if (roleFromClaim.equals(Roles.INTERNAL) && (allowInternal.isEmpty() || !allowInternal.get())) {
            throw new RuntimeException("Insufficient access");
        }
        if (Roles.ADMIN.equals(role.get())) {
            if (!roleFromClaim.equals(Roles.ADMIN)) {
                throw new RuntimeException("Insufficient access");
            }
        }
        if (Roles.SYSTEM.equals(role.get())) {
            if (roleFromClaim.equals(Roles.USER)) {
                throw new RuntimeException("Insufficient access");
            }

        }
    }

}
