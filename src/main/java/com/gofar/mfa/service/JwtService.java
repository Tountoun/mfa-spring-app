package com.gofar.mfa.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${app.jwt.secret-key}")
    private String secretKey;

    @Value("${app.jwt.expiration-time}")
    private long jwtExpirationTime;

    @Value("${app.jwt.pre-auth-expiration-time}")
    private long preAuthExpirationTime;

    // Claim to indicate that the token is temporary
    private static final String CLAIM_PRE_AUTH = "pre_auth";

    /**
     * Generate a token for the user
     * @param userDetails the details of the user
     * @return the token
     */
    public String generateToken(UserDetails userDetails) {
        return buildToken(Map.of(CLAIM_PRE_AUTH, false), userDetails.getUsername(), jwtExpirationTime);
    }

    /**
     * Generate a pre-authentication token for the user
     * @param username the username of the user
     * @return the pre-authentication token
     */
    public String generatePreAuthToken(String username) {
        return buildToken(Map.of(CLAIM_PRE_AUTH, true), username, preAuthExpirationTime);
    }

    /**
     * Extract the username from the token
     * @param token the token
     * @return the username
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract the expiration date from the token
     * @param token the token
     * @return the expiration date
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Check if the token is valid
     * @param token token to check
     * @param userDetails the details of the user
     * @return true if the token is valid, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * Check if the pre-authentication token is valid
     * @param token the token
     * @param username the username of the user
     * @return true if the token is valid, false otherwise
     */
    public boolean isPreAuthTokenValid(String token, String username) {
        try {
            final String tokenUsername = extractUsername(token);
            return tokenUsername.equals(username)
                    && !isTokenExpired(token)
                    && isPreAuthToken(token);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if the token is a pre-authentication token
     * @param token the token
     * @return true if the token is a pre-authentication token, false otherwise
     */
    public boolean isPreAuthToken(String token) {
        try {
            return Boolean.TRUE.equals(extractClaim(token, claims -> claims.get(CLAIM_PRE_AUTH, Boolean.class)));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract a claim from the token
     * @param token the token
     * @param claimsResolver a function to extract the claim
     * @return the claim
     * @param <T> the type of the claim
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Build a token with extra claims
     * @param extraClaims the extra claims
     * @param subject the subject
     * @param expirationTime the expiration time
     * @return the token
     */
    private String buildToken(Map<String, Object> extraClaims, String subject, long expirationTime) {
        return Jwts.builder()
                .subject(subject)
                .claims(extraClaims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSingingKey())
                .compact();
    }

    /**
     * Extract all claims from the token
     * @param token the token
     * @return the claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSingingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Check if the token is expired
     * @param token the token
     * @return true if the token is expired, false otherwise
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Get the signing key of the token
     * @return the signing key
     */
    private SecretKey getSingingKey() {
        byte[] keyBytes = Decoders.BASE64.decode(
                Base64.getEncoder().encodeToString(secretKey.getBytes())
        );
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
