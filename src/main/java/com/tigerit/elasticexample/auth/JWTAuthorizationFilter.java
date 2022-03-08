package com.tigerit.elasticexample.auth;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import static com.tigerit.elasticexample.auth.SecurityConstants.*;
import static com.tigerit.elasticexample.utils.ResponseMessages.*;
public class JWTAuthorizationFilter extends GenericFilterBean {

    private static Logger logger = LoggerFactory.getLogger(JWTAuthorizationFilter.class);

    private JWT jwt;

    public JWTAuthorizationFilter(JWT jwt) {
        this.jwt = jwt;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        String randomCode = UUID.randomUUID().toString().substring(0, 6);
        MDC.put("random_code", randomCode);
        try {
            logger.debug("Calling jwt to resolve access token from request");
            String accessToken = jwt.resolveToken((HttpServletRequest) request);
            String tokenType = jwt.getTokenType(accessToken);
            if (accessToken != null && !tokenType.equalsIgnoreCase(ACCESS_TOKEN)) {
                throw new AuthenticationServiceException(INVALID_TOKEN);
            }
            logger.debug("accessToken: {}, tokenType: {}", accessToken, tokenType);
            logger.debug("Calling jwt to resolve claims from request");
            Claims claims = jwt.resolveClaims((HttpServletRequest) request);
            if (accessToken != null && claims != null
                    && jwt.validateClaims(claims)) {
                MDC.put("logged_user", jwt.getUsername(claims));
                logger.debug("Calling getAuthentication with claims, httpRequest and token");
                Authentication authentication = jwt.getAuthentication(claims, (HttpServletRequest) request, accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception exception) {
            throw exception;
        }
        try {
            chain.doFilter(request, response);
        }
        catch (Exception e) {
            logger.warn("Global Exception caught", e);
            throw e;
        } finally {
            MDC.remove("logged_user");
            MDC.remove("random_code");
        }
    }
}
