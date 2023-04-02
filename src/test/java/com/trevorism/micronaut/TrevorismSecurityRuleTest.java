package com.trevorism.micronaut;

import com.trevorism.secure.Roles;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TrevorismSecurityRuleTest {

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


    public class TestAuthentication implements Authentication {
        private final String role;
        private final String issuer;

        public TestAuthentication(String role, String issuer) {
            this.role = role;
            this.issuer = issuer;
        }

        @Override
        public Map<String, Object> getAttributes() {
            HashMap<String, Object> map = new HashMap<>();
            map.put("iss", issuer);
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