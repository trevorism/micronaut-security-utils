package com.trevorism.micronaut;

import com.trevorism.PropertiesProvider;
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
import io.micronaut.web.router.RouteAttributes;
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
    private static final String EXPECTED_ISSUER = "https://trevorism.com";

    @Inject
    PropertiesProvider propertiesProvider;

    @Override
    public int getOrder() {
        return -1000;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, Authentication authentication) {
        RouteMatch<?> routeMatch = RouteAttributes.getRouteMatch(request).orElse(null);
        if (routeMatch instanceof MethodBasedRouteMatch methodBasedRouteMatch && methodBasedRouteMatch.hasAnnotation(Secure.class)) {
            return evaluateSecureAnnotation(authentication, methodBasedRouteMatch, request);
        }
        return Mono.just(SecurityRuleResult.ALLOWED);
    }

    private Mono<SecurityRuleResult> evaluateSecureAnnotation(Authentication authentication, MethodBasedRouteMatch<?,?> methodBasedRouteMatch, HttpRequest<?> request) {
        AnnotationValue<Secure> secureAnnotation = methodBasedRouteMatch.getAnnotation(Secure.class);
        ClaimValidationResult validationResult = validateClaimDetails(secureAnnotation, authentication);
        if (!validationResult.failed()) {
            return Mono.just(SecurityRuleResult.ALLOWED);
        }

        log.info("Rejected request [{} {}]: {}", request.getMethod(), request.getPath(), validationResult.reason());
        if (validationResult.unauthenticated()) {
            return Mono.just(SecurityRuleResult.UNKNOWN);
        }
        return Mono.just(SecurityRuleResult.REJECTED);
    }

    public boolean validateClaims(AnnotationValue<Secure> annotation, Authentication authentication) {
        return !validateClaimDetails(annotation, authentication).failed();
    }

    private ClaimValidationResult validateClaimDetails(AnnotationValue<Secure> annotation, Authentication authentication) {
        ClaimValidationResult inputValidation = validateInputs(annotation, authentication);
        if (inputValidation.failed()) {
            return inputValidation;
        }

        ClaimValidationResult issuerValidation = validateIssuer(authentication);
        if (issuerValidation.failed()) {
            return issuerValidation;
        }

        return validateAuthenticationAgainstAnnotation(annotation, authentication);
    }

    private ClaimValidationResult validateInputs(AnnotationValue<Secure> annotation, Authentication authentication) {
        if (authentication == null || authentication.getRoles() == null || authentication.getRoles().isEmpty()) {
            return ClaimValidationResult.unauthenticated("Unable to parse token; identity role is missing");
        }
        if (annotation == null) {
            return ClaimValidationResult.unauthorized("Unable to validate a method without @Secure annotation");
        }
        return ClaimValidationResult.allowed();
    }

    private ClaimValidationResult validateIssuer(Authentication authentication) {
        Object issuerObject = authentication.getAttributes().get("issuer");
        if (!(issuerObject instanceof String issuer)) {
            return ClaimValidationResult.unauthenticated("Issuer claim is missing");
        }
        if (!EXPECTED_ISSUER.equals(issuer)) {
            return ClaimValidationResult.unauthenticated("Unexpected issuer: " + issuer);
        }
        return ClaimValidationResult.allowed();
    }

    private ClaimValidationResult validateAuthenticationAgainstAnnotation(AnnotationValue<Secure> annotation, Authentication authentication) {
        ClaimValidationResult roleValidation = validateRole(annotation.stringValue(), annotation.booleanValue("allowInternal"), authentication.getRoles().stream().findFirst());
        if (roleValidation.failed()) {
            return roleValidation;
        }

        ClaimValidationResult audienceValidation = validateAudience(annotation.booleanValue("authorizeAudience"), authentication.getAttributes().get("audience"));
        if (audienceValidation.failed()) {
            return audienceValidation;
        }

        return validatePermissions(annotation.stringValue("permissions"), authentication.getAttributes().get("permissions"));
    }

    private ClaimValidationResult validateAudience(Optional<Boolean> authorizeAudience, Object audience) {
        if (authorizeAudience.isEmpty() || !authorizeAudience.get()) {
            return ClaimValidationResult.allowed();
        }
        if (!(audience instanceof Set<?> audienceSet)) {
            return ClaimValidationResult.unauthorized("Audience claim is missing");
        }

        String clientId = propertiesProvider.getProperty("clientId");
        if (clientId == null || clientId.isBlank()) {
            return ClaimValidationResult.unauthorized("clientId configuration is missing");
        }
        if (!audienceSet.contains(clientId)) {
            return ClaimValidationResult.unauthorized("Audience does not contain configured clientId");
        }
        return ClaimValidationResult.allowed();
    }

    private static ClaimValidationResult validatePermissions(Optional<String> permissions, Object claimedPermissions) {
        if (permissions.isEmpty() || permissions.get().isEmpty()) {
            return ClaimValidationResult.allowed();
        }
        if (!(claimedPermissions instanceof String permissionString)) {
            return ClaimValidationResult.unauthorized("Permissions claim is missing");
        }

        for (char permission : permissions.get().toCharArray()) {
            if (!permissionString.contains(String.valueOf(permission))) {
                return ClaimValidationResult.unauthorized("Insufficient permissions");
            }
        }
        return ClaimValidationResult.allowed();
    }

    private static ClaimValidationResult validateRole(Optional<String> role, Optional<Boolean> allowInternal, Optional<String> claimRole) {
        if (claimRole.isEmpty()) {
            return ClaimValidationResult.unauthenticated("Role claim is missing");
        }

        String roleFromClaim = claimRole.get();
        if (Roles.INTERNAL.equals(roleFromClaim)) {
            if (allowInternal.isPresent() && allowInternal.get()) {
                return ClaimValidationResult.allowed();
            }
            return ClaimValidationResult.unauthorized("Internal role is not allowed");
        }

        String requiredRole = role.orElse("");
        if (Roles.ADMIN.equals(requiredRole) && !Roles.ADMIN.equals(roleFromClaim)) {
            return ClaimValidationResult.unauthorized("Admin role is required");
        }
        if (Roles.SYSTEM.equals(requiredRole) && !Roles.ADMIN.equals(roleFromClaim) && !Roles.SYSTEM.equals(roleFromClaim)) {
            return ClaimValidationResult.unauthorized("System role is required");
        }
        if (Roles.TENANT_ADMIN.equals(requiredRole) && !Roles.ADMIN.equals(roleFromClaim) && !Roles.SYSTEM.equals(roleFromClaim) && !Roles.TENANT_ADMIN.equals(roleFromClaim)) {
            return ClaimValidationResult.unauthorized("Tenant admin role is required");
        }
        return ClaimValidationResult.allowed();
    }
}
