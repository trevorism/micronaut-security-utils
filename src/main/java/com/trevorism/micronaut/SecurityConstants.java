package com.trevorism.micronaut;

public final class SecurityConstants {

    private SecurityConstants() {
    }

    public static final class Claims {
        public static final String ISSUER = "issuer";
        public static final String AUDIENCE = "audience";
        public static final String SUBJECT = "subject";
        public static final String ID = "id";
        public static final String TYPE = "type";
        public static final String TENANT = "tenant";
        public static final String PERMISSIONS = "permissions";
        public static final String EXPECTED_ISSUER = "https://trevorism.com";

        private Claims() {
        }
    }

    public static final class Annotation {
        public static final String ALLOW_INTERNAL = "allowInternal";
        public static final String AUTHORIZE_AUDIENCE = "authorizeAudience";
        public static final String PERMISSIONS = "permissions";

        private Annotation() {
        }
    }

    public static final class Config {
        public static final String CLIENT_ID = "clientId";
        public static final String SIGNING_KEY = "signingKey";

        private Config() {
        }
    }

    public static final class Http {
        public static final String AUTHORIZATION_HEADER = "Authorization";
        public static final String SESSION_COOKIE = "session";
        public static final String BEARER_PREFIX = "bearer ";

        private Http() {
        }
    }

    public static final class Messages {
        public static final String REJECTED_REQUEST = "Rejected request [{} {}]: {}";
        public static final String MISSING_AUTHENTICATION = "Authentication is missing. Token may be absent, invalid, or expired";
        public static final String MISSING_ROLE_CLAIMS = "Authentication is present but contains no role claims";
        public static final String MISSING_SECURE_ANNOTATION = "Unable to validate a method without @Secure annotation";
        public static final String MISSING_ISSUER = "Issuer claim is missing";
        public static final String UNEXPECTED_ISSUER = "Unexpected issuer: ";
        public static final String MISSING_AUDIENCE = "Audience claim is missing";
        public static final String MISSING_CLIENT_ID_CONFIG = "clientId configuration is missing";
        public static final String INVALID_AUDIENCE = "Audience does not contain configured clientId";
        public static final String INSUFFICIENT_PERMISSIONS = "Insufficient permissions";
        public static final String MISSING_ROLE_CLAIM = "Role claim is missing";
        public static final String INTERNAL_ROLE_NOT_ALLOWED = "Internal role is not allowed";
        public static final String ADMIN_ROLE_REQUIRED = "Admin role is required";
        public static final String SYSTEM_ROLE_REQUIRED = "System role is required";
        public static final String TENANT_ADMIN_ROLE_REQUIRED = "Tenant admin role is required";
        public static final String TOKEN_REJECTED = "Token rejected: {}";
        public static final String TOKEN_REJECTION_DETAILS = "Token rejection details";

        private Messages() {
        }
    }
}

