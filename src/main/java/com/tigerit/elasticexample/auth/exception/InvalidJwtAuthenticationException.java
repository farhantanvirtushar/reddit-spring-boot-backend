package com.tigerit.elasticexample.auth.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidJwtAuthenticationException extends AuthenticationException {
    public InvalidJwtAuthenticationException(String msg, Exception ex) {
        super(msg, ex);
    }
}
