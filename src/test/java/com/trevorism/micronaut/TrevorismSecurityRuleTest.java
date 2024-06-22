package com.trevorism.micronaut;

import com.trevorism.PropertiesProvider;
import com.trevorism.secure.Permissions;
import com.trevorism.secure.Roles;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class TrevorismSecurityRuleTest {

    @Test
    void getOrder() {
        assertEquals(-1000, new TrevorismSecurityRule().getOrder());
    }

    @Test
    void validateValidClaims() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                Map.of("value", Roles.USER)), new TestAuthentication(Roles.USER, "https://trevorism.com"));
        assertTrue(result);
    }

    @Test
    void validateInvalidClaims_WithBadIssuer() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                Map.of("value", Roles.ADMIN)), new TestAuthentication(Roles.USER, "https://trevorism"));
        assertFalse(result);
    }

    @Test
    void validateInvalidClaims_WithNoAuth() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                Map.of("value", Roles.ADMIN)), null);
        assertFalse(result);
    }

    @Test
    void validateInvalidClaims_WithNotEnoughPrivilege() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                Map.of("value", Roles.ADMIN)), new TestAuthentication(Roles.USER, "https://trevorism.com"));
        assertFalse(result);
    }

    @Test
    void validateValidSystemClaim_WithAllowInternal() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                Map.of("value", Roles.SYSTEM, "allowInternal", true)), new TestAuthentication(Roles.INTERNAL, "https://trevorism.com"));
        assertTrue(result);
    }

    @Test
    void validateValidClaimsValidAudience() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        rule.propertiesProvider = s -> "testAudienceGuid";
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                Map.of("value", Roles.USER, "authorizeAudience", true)),
                new TestAuthentication(Roles.USER, "https://trevorism.com", "testAudienceGuid", null));
        assertTrue(result);
    }

    @Test
    void validateValidClaimsInvalidAudience() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        rule.propertiesProvider = s -> "testAudienceGuid";
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                        Map.of("value", Roles.USER, "authorizeAudience", true)),
                new TestAuthentication(Roles.USER, "https://trevorism.com", "invalid", null));
        assertFalse(result);
    }

    @Test
    void validateValidClaimsValidPermissions() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                        Map.of("value", Roles.USER, "permissions", Permissions.CREATE)),
                new TestAuthentication(Roles.USER, "https://trevorism.com", null, "CRUDE"));
        assertTrue(result);
    }

    @Test
    void validateValidClaimsInvalidPermissions() {
        TrevorismSecurityRule rule = new TrevorismSecurityRule();
        boolean result = rule.validateClaims(new AnnotationValue<>("Secure",
                        Map.of("value", Roles.USER, "permissions", "CE")),
                new TestAuthentication(Roles.USER, "https://trevorism.com", null, "C"));
        assertFalse(result);
    }

    public class TestAuthentication implements Authentication {
        private final String role;
        private final String issuer;
        private final String audience;
        private final String permissions;

        public TestAuthentication(String role, String issuer) {
            this.role = role;
            this.issuer = issuer;
            this.audience = null;
            this.permissions = null;
        }

        public TestAuthentication(String role, String issuer, String audience, String permissions) {
            this.role = role;
            this.issuer = issuer;
            this.audience = audience;
            this.permissions = permissions;
        }

        @Override
        public Map<String, Object> getAttributes() {
            HashMap<String, Object> map = new HashMap<>();
            map.put("issuer", issuer);
            if(audience != null) {
                map.put("audience", Set.of(audience));
            }
            if(permissions != null) {
                map.put("permissions", permissions);
            }
            return map;
        }

        @Override
        public Collection<String> getRoles() {
            return Arrays.asList(role);
        }

        @Override
        public String getName() {
            return null;
        }
    }
}