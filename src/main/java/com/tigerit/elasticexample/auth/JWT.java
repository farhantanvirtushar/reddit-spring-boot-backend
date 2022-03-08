package com.tigerit.elasticexample.auth;

import com.tigerit.elasticexample.auth.exception.InvalidJwtAuthenticationException;
import com.tigerit.elasticexample.model.RedditUserDetails;
import io.jsonwebtoken.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.security.Key;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;


import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import static com.tigerit.elasticexample.auth.SecurityConstants.*;
import static com.tigerit.elasticexample.utils.ResponseMessages.*;
import static com.tigerit.elasticexample.utils.SessionKey.*;

@Component
public class JWT {

    private JwtParser jwtParser;
    String secretKey = "SuperSecretKey";

    private static Logger logger = LoggerFactory.getLogger(JWT.class);;

    @PostConstruct
    protected void init() {
        this.jwtParser = Jwts.parser().setSigningKey(secretKey.getBytes());
    }

    public String createToken(String username,String tokenType) {


        Claims claims = Jwts.claims().setSubject(username);


        return Jwts.builder()
                .setClaims(claims)
                .setHeaderParam(TOKEN_TYPE, tokenType)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 600000))
                .signWith(SignatureAlgorithm.HS512,
                        secretKey.getBytes())
                .compact();
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(TOKEN_HEADER);
        if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(TOKEN_PREFIX.length());
        }
        System.out.println("token not found");
        return null;
    }

    public Claims resolveClaims(HttpServletRequest req) {
        try {
            logger.debug("Trying to resolve claims token ");
            String bearerToken = req.getHeader(TOKEN_HEADER);
            if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
                return parseJwtClaims(bearerToken.substring(TOKEN_PREFIX.length()));
            }
            return null;
        } catch (ExpiredJwtException ex) {
            logger.debug("Could not parse jwt claims, Token Expired ", ex);
            req.setAttribute(EXPIRED, ex.getMessage());
            throw new InvalidJwtAuthenticationException(EXPIRED_TOKEN, ex);
        } catch (Exception ex) {
            logger.debug("Could not parse jwt claims, Token Invalid ", ex);
            req.setAttribute(INVALID, ex.getMessage());
            throw new InvalidJwtAuthenticationException(INVALID_TOKEN, ex);
        }
    }

    private Claims parseJwtClaims(String token) {
        return jwtParser.parseClaimsJws(token).getBody();
    }

    public String getTokenType(String token) {
//        logger.debug("Parsing token type from token : {}", token);
        try {
            if (token != null) {
                return (String) jwtParser.parse(token).getHeader().get(TOKEN_TYPE);
            }
            logger.debug("Token is Null, returning TYPE : null");
            return null;
        } catch (ExpiredJwtException ex) {
            logger.debug("Could not parse jwt claims, Token Expired ", ex);
            throw new InvalidJwtAuthenticationException(EXPIRED_TOKEN, ex);
        } catch (Exception ex) {
            logger.debug("Could not parse jwt claims, Token Invalid ", ex);
            throw new InvalidJwtAuthenticationException(INVALID_TOKEN, ex);
        }
    }

    public boolean validateClaims(Claims claims) throws InvalidJwtAuthenticationException {
        try {
            logger.debug("Validating jwt token Claims");
            return claims.getExpiration().after(new Date());
        } catch (Exception e) {
            logger.debug("Exception while parsing Claims");
            throw new InvalidJwtAuthenticationException("Expired or invalid JWT token", e);
        }
    }


    public String getUsername(Claims claims) {
        return claims.getSubject();
    }

    private List<String> getRoles(Claims claims) {
        return (List<String>) claims.get("roles");
    }

    public Authentication getAuthentication(Claims claims, HttpServletRequest request, String token) {
        logger.debug("Authentication request of token received");
        String username = getUsername(claims);
        String tokenType = getTokenType(token);
        List<String> roles = new ArrayList<String>();
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        if (tokenType.equals(ACCESS_TOKEN)) {
            roles = getRoles(claims);
            logger.debug("tokenType : access_token, username : {}, -> roles : {}", username, roles);
            roles.forEach(role -> grantedAuthorities.add(new SimpleGrantedAuthority(role)));
        }
        UserDetails userDetails = new RedditUserDetails(username, null, roles);
        request.getSession().setAttribute(USER_DETAILS, userDetails);
        request.getSession().setAttribute(TYPE_OF_TOKEN, tokenType);
        return new UsernamePasswordAuthenticationToken(userDetails, "", grantedAuthorities);
    }

}
