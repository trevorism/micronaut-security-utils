package com.trevorism.micronaut;

import com.trevorism.*;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Singleton
public class TrevorismAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {

    public static final String BEARER_PREFIX = "bearer ";
    private PropertiesProvider propertiesProvider;
    private static final Logger log = LoggerFactory.getLogger(TrevorismAuthenticationFetcher.class.getName());

    public TrevorismAuthenticationFetcher() {
        propertiesProvider = new ClasspathBasedPropertiesProvider();
    }

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        try {
            String sessionToken = getTokenFromSessionCookie(request);
            String bearerToken = getTokenFromBearerToken(request);
            if (bearerToken == null && sessionToken == null) {
                return Mono.empty();
            }
            return publishToken(Objects.requireNonNullElse(bearerToken, sessionToken));
        } catch (Exception e) {
            log.warn("Failed to authenticate", e);
            return Mono.empty();
        }
    }

    private Publisher<Authentication> publishToken(String bearerToken) {
        ClaimProperties claimProperties = ClaimsProvider.getClaims(bearerToken, getSigningKey());
        Map<String, Object> claimMap = Map.of("type", claimProperties.getType(),
                "iss", claimProperties.getIssuer(),
                "id", claimProperties.getId(),
                "aud", claimProperties.getAudience());
        if (claimProperties.getTenant() != null) {
            claimMap = new HashMap<>(claimMap);
            claimMap.put("tenant", claimProperties.getTenant());
        }

        return Mono.just(Authentication.build(claimProperties.getSubject(), List.of(claimProperties.getRole()), claimMap));
    }

    private String getSigningKey() {
        try {
            String key = propertiesProvider.getProperty("signingKey");
            if(key == null || key.isBlank())
                throw new Exception();
            return key;
        } catch (Exception e) {
            throw new SigningKeyException();
        }
    }

    private String getTokenFromBearerToken(HttpRequest<?> request) {
        try {
            String authString = request.getHeaders().get("Authorization");
            if (authString == null || !authString.toLowerCase().startsWith(BEARER_PREFIX)) {
                return null;
            }
            return authString.substring(BEARER_PREFIX.length());
        } catch (Exception ignored) {
            return null;
        }
    }

    private String getTokenFromSessionCookie(HttpRequest<?> request) {
        try {
            return request.getCookies().get("session").getValue();
        } catch (Exception ignored) {
            return null;
        }
    }

    @Override
    public int getOrder() {
        return -1000;
    }
}
