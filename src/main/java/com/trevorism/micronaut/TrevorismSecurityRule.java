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
        if (routeMatch instanceof MethodBasedRouteMatch methodBasedRouteMatch && methodBasedRouteMatch.getAnnotationMetadata().hasDeclaredAnnotation(Secure.class)) {
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

        log.info(SecurityConstants.Messages.REJECTED_REQUEST, request.getMethod(), request.getPath(), validationResult.reason());
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
        if (authentication == null) {
            return ClaimValidationResult.unauthenticated(SecurityConstants.Messages.MISSING_AUTHENTICATION);
        }
        if (authentication.getRoles() == null || authentication.getRoles().isEmpty()) {
            return ClaimValidationResult.unauthenticated(SecurityConstants.Messages.MISSING_ROLE_CLAIMS);
        }
        if (annotation == null) {
            return ClaimValidationResult.unauthorized(SecurityConstants.Messages.MISSING_SECURE_ANNOTATION);
        }
        return ClaimValidationResult.allowed();
    }

    private ClaimValidationResult validateIssuer(Authentication authentication) {
        Object issuerObject = authentication.getAttributes().get(SecurityConstants.Claims.ISSUER);
        if (!(issuerObject instanceof String issuer)) {
            return ClaimValidationResult.unauthenticated(SecurityConstants.Messages.MISSING_ISSUER);
        }
        if (!SecurityConstants.Claims.EXPECTED_ISSUER.equals(issuer)) {
            return ClaimValidationResult.unauthenticated(SecurityConstants.Messages.UNEXPECTED_ISSUER + issuer);
        }
        return ClaimValidationResult.allowed();
    }

    private ClaimValidationResult validateAuthenticationAgainstAnnotation(AnnotationValue<Secure> annotation, Authentication authentication) {
        Optional<String> claimRole = authentication.getRoles().stream().findFirst();
        ClaimValidationResult roleValidation = validateRole(annotation.stringValue(), annotation.booleanValue(SecurityConstants.Annotation.ALLOW_INTERNAL), claimRole);
        if (roleValidation.failed()) {
            return roleValidation;
        }

        ClaimValidationResult audienceValidation = validateAudience(annotation.booleanValue(SecurityConstants.Annotation.AUTHORIZE_AUDIENCE), authentication.getAttributes().get(SecurityConstants.Claims.AUDIENCE));
        if (audienceValidation.failed()) {
            return audienceValidation;
        }

        if (Roles.ADMIN.equals(claimRole.orElse(""))) {
            return ClaimValidationResult.allowed();
        }

        return validatePermissions(annotation.stringValue(SecurityConstants.Annotation.PERMISSIONS), authentication.getAttributes().get(SecurityConstants.Claims.PERMISSIONS));
    }

    private ClaimValidationResult validateAudience(Optional<Boolean> authorizeAudience, Object audience) {
        if (authorizeAudience.isEmpty() || !authorizeAudience.get()) {
            return ClaimValidationResult.allowed();
        }
        if (!(audience instanceof Set<?> audienceSet)) {
            return ClaimValidationResult.unauthorized(SecurityConstants.Messages.MISSING_AUDIENCE);
        }

        String clientId = propertiesProvider.getProperty(SecurityConstants.Config.CLIENT_ID);
        if (clientId == null || clientId.isBlank()) {
            return ClaimValidationResult.unauthorized(SecurityConstants.Messages.MISSING_CLIENT_ID_CONFIG);
        }
        if (!audienceSet.contains(clientId)) {
            return ClaimValidationResult.unauthorized(SecurityConstants.Messages.INVALID_AUDIENCE);
        }
        return ClaimValidationResult.allowed();
    }

    private static ClaimValidationResult validatePermissions(Optional<String> permissions, Object claimedPermissions) {
        if (permissions.isEmpty() || permissions.get().isEmpty()) {
            return ClaimValidationResult.allowed();
        }
        if (!(claimedPermissions instanceof String permissionString)) {
            return ClaimValidationResult.allowed();
        }

        for (char permission : permissions.get().toCharArray()) {
            if (!permissionString.contains(String.valueOf(permission))) {
                return ClaimValidationResult.unauthorized(SecurityConstants.Messages.INSUFFICIENT_PERMISSIONS);
            }
        }
        return ClaimValidationResult.allowed();
    }

    private static ClaimValidationResult validateRole(Optional<String> role, Optional<Boolean> allowInternal, Optional<String> claimRole) {
        if (claimRole.isEmpty()) {
            return ClaimValidationResult.unauthenticated(SecurityConstants.Messages.MISSING_ROLE_CLAIM);
        }

        String roleFromClaim = claimRole.get();
        if (Roles.INTERNAL.equals(roleFromClaim)) {
            if (allowInternal.isPresent() && allowInternal.get()) {
                return ClaimValidationResult.allowed();
            }
            return ClaimValidationResult.unauthorized(SecurityConstants.Messages.INTERNAL_ROLE_NOT_ALLOWED);
        }

        String requiredRole = role.orElse("");
        if (Roles.ADMIN.equals(requiredRole) && !Roles.ADMIN.equals(roleFromClaim)) {
            return ClaimValidationResult.unauthorized(SecurityConstants.Messages.ADMIN_ROLE_REQUIRED);
        }
        if (Roles.SYSTEM.equals(requiredRole) && !Roles.ADMIN.equals(roleFromClaim) && !Roles.SYSTEM.equals(roleFromClaim)) {
            return ClaimValidationResult.unauthorized(SecurityConstants.Messages.SYSTEM_ROLE_REQUIRED);
        }
        if (Roles.TENANT_ADMIN.equals(requiredRole) && !Roles.ADMIN.equals(roleFromClaim) && !Roles.SYSTEM.equals(roleFromClaim) && !Roles.TENANT_ADMIN.equals(roleFromClaim)) {
            return ClaimValidationResult.unauthorized(SecurityConstants.Messages.TENANT_ADMIN_ROLE_REQUIRED);
        }
        return ClaimValidationResult.allowed();
    }
}
