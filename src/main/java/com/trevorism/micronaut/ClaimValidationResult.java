package com.trevorism.micronaut;

public record ClaimValidationResult(FailureType failureType, String reason) {

    public ClaimValidationResult {
        if (failureType == null) {
            throw new IllegalArgumentException("failureType cannot be null");
        }
        reason = reason == null ? "" : reason;
    }

    public static ClaimValidationResult allowed() {
        return new ClaimValidationResult(FailureType.NONE, "");
    }

    public static ClaimValidationResult unauthenticated(String reason) {
        return new ClaimValidationResult(FailureType.UNAUTHENTICATED, reason);
    }

    public static ClaimValidationResult unauthorized(String reason) {
        return new ClaimValidationResult(FailureType.UNAUTHORIZED, reason);
    }

    public boolean failed() {
        return failureType != FailureType.NONE;
    }

    public boolean unauthenticated() {
        return failureType == FailureType.UNAUTHENTICATED;
    }
}

