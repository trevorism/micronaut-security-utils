package com.trevorism;

public class SigningKeyException extends RuntimeException{
    public SigningKeyException() {
        super("Unable to retrieve signing key from properties file");
    }
}
