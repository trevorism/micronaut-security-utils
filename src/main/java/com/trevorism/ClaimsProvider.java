package com.trevorism;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;

public class ClaimsProvider {

    public static final String DB_ID = "dbId";
    public static final String ROLE = "role";
    public static final String ENTITY_TYPE = "entityType";

    public static ClaimProperties getClaims(String bearerToken, String signingKey) {
        Key decodedKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey));
        Jws<Claims> parsedClaims = Jwts.parserBuilder()
                .setAllowedClockSkewSeconds(120)
                .setSigningKey(decodedKey)
                .build()
                .parseClaimsJws(bearerToken);

        return createClaimProperties(parsedClaims);
    }

    private static ClaimProperties createClaimProperties(Jws<Claims> parsedClaims) {
        ClaimProperties claimProperties = new ClaimProperties();
        Claims claims = parsedClaims.getBody();
        claimProperties.setId(claims.get(DB_ID, String.class));
        claimProperties.setSubject(claims.getSubject());
        claimProperties.setAudience(claims.getAudience());
        claimProperties.setIssuer(claims.getIssuer());
        claimProperties.setRole(claims.get(ROLE, String.class));
        claimProperties.setType(claims.get(ENTITY_TYPE, String.class));
        return claimProperties;
    }
}
