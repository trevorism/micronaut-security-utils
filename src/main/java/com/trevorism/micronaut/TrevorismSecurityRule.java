package com.trevorism.micronaut;

import com.trevorism.AuthenticationFailedException;
import com.trevorism.PropertiesProvider;
import com.trevorism.secure.Roles;
import com.trevorism.secure.Secure;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecuredAnnotationRule;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.Set;

@Singleton
@Replaces(SecuredAnnotationRule.class)
public class TrevorismSecurityRule implements SecurityRule<HttpRequest<?>> {

    private static final Logger log = LoggerFactory.getLogger(TrevorismSecurityRule.class);

    @Inject
    PropertiesProvider propertiesProvider;

    @Override
    public int getOrder() {
        return -1000;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, Authentication authentication) {
        RouteMatch<?> routeMatch = request.getAttribute(HttpAttributes.ROUTE_MATCH, RouteMatch.class).orElse(null);
        if (routeMatch instanceof MethodBasedRouteMatch methodBasedRouteMatch) {
            if (methodBasedRouteMatch.hasAnnotation(Secure.class)) {
                return allowOrRejectBasedOnSecureAnnotationAndIncomingClaims(authentication, methodBasedRouteMatch);
            }
        }
        return Mono.just(SecurityRuleResult.ALLOWED);

    }

    private Mono<SecurityRuleResult> allowOrRejectBasedOnSecureAnnotationAndIncomingClaims(Authentication authentication, MethodBasedRouteMatch methodBasedRouteMatch) {
        AnnotationValue<Secure> secureAnnotation = methodBasedRouteMatch.getAnnotation(Secure.class);
        if (validateClaims(secureAnnotation, authentication))
            return Mono.just(SecurityRuleResult.ALLOWED);
        else
            return Mono.just(SecurityRuleResult.REJECTED);
    }

    public boolean validateClaims(AnnotationValue<Secure> annotation, Authentication authentication) {
        try {
            validateInputs(annotation, authentication);
            validateIssuer(authentication);
            validateAuthenticationAgainstAnnotation(annotation, authentication);
            return true;
        } catch (Exception e) {
            log.debug("Failed to validate claim", e);
            return false;
        }
    }

    private void validateInputs(AnnotationValue<Secure> annotation, Authentication authentication) {
        if (authentication == null || authentication.getRoles().isEmpty()) {
            throw new AuthenticationFailedException("Unable to parse incoming token; cannot find identity's role");
        }
        if (annotation == null) {
            throw new AuthenticationFailedException("Unable to validate against a method without the @Secure annotation");
        }
    }

    private void validateIssuer(Authentication authentication) {
        String issuer = authentication.getAttributes().get("issuer").toString();
        if (!"https://trevorism.com".equals(issuer)) {
            throw new AuthenticationFailedException("Unexpected issuer: ${issuer}");
        }
    }

    private void validateAuthenticationAgainstAnnotation(AnnotationValue<Secure> annotation, Authentication authentication) {
        validateRole(annotation.stringValue(), annotation.booleanValue("allowInternal"), authentication.getRoles().stream().findFirst());
        validateAudience(annotation.booleanValue("authorizeAudience"), authentication.getAttributes().get("audience"));
        validatePermissions(annotation.stringValue("permissions"), authentication.getAttributes().get("permissions"));
    }

    private void validateAudience(Optional<Boolean> authorizeAudience, Object audience) {
        if (authorizeAudience.isEmpty() || !authorizeAudience.get()) {
            return;
        }
        if (!(audience instanceof Set audienceSet)) {
            throw new AuthenticationFailedException("Audience not found in token");
        }
        String clientId = propertiesProvider.getProperty("clientId");
        if (!audienceSet.contains(clientId)) {
            throw new AuthenticationFailedException("Audience not found in token");
        }
    }

    private static void validatePermissions(Optional<String> permissions, Object claimedPermissions) {
        if (permissions.isEmpty() || permissions.get().isEmpty()) {
            return;
        }
        if (!(claimedPermissions instanceof String permissionString)) {
            throw new AuthenticationFailedException("Permissions not found in token");
        }
        for (char permission : permissions.get().toCharArray()) {
            if (!permissionString.contains(String.valueOf(permission))) {
                throw new AuthenticationFailedException("Insufficient access");
            }
        }
    }

    private static void validateRole(Optional<String> role, Optional<Boolean> allowInternal, Optional<String> claimRole) {
        String roleFromClaim = claimRole.get();
        if (roleFromClaim.equals(Roles.INTERNAL)) {
            if(allowInternal.isPresent() && allowInternal.get()){
                return;
            }
            throw new AuthenticationFailedException("Insufficient access");
        }
        if (Roles.ADMIN.equals(role.get())) {
            if (!roleFromClaim.equals(Roles.ADMIN)) {
                throw new AuthenticationFailedException("Insufficient access");
            }
        }
        if (Roles.SYSTEM.equals(role.get())) {
            if (!roleFromClaim.equals(Roles.ADMIN) && !roleFromClaim.equals(Roles.SYSTEM))
                throw new AuthenticationFailedException("Insufficient access");
            }
        if (Roles.TENANT_ADMIN.equals(role.get())) {
            if (!roleFromClaim.equals(Roles.ADMIN) && !roleFromClaim.equals(Roles.SYSTEM) && !roleFromClaim.equals(Roles.TENANT_ADMIN)) {
                throw new AuthenticationFailedException("Insufficient access");
            }
        }
    }

}
