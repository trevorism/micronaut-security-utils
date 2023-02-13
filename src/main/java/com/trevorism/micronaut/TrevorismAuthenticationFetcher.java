package com.trevorism.micronaut;

import com.trevorism.ClaimProperties;
import com.trevorism.ClaimsProvider;
import com.trevorism.ClasspathBasedPropertiesProvider;
import com.trevorism.PropertiesProvider;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.*;

@Singleton
public class TrevorismAuthenticationFetcher implements AuthenticationFetcher {

    public static final String BEARER_PREFIX = "bearer ";

    private PropertiesProvider propertiesProvider;

    TrevorismAuthenticationFetcher() {
        propertiesProvider = new ClasspathBasedPropertiesProvider();
    }

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        String sessionToken = getTokenFromSessionCookie(request);
        String bearerToken = getTokenFromBearerToken(request);
        if(bearerToken == null && sessionToken == null){
            return Mono.empty();
        }
        return publishToken(Objects.requireNonNullElse(bearerToken, sessionToken));
    }

    private Publisher<Authentication> publishToken(String bearerToken) {
        ClaimProperties claimProperties = ClaimsProvider.getClaims(bearerToken, propertiesProvider.getProperty("signingKey"));
        return Mono.just(Authentication.build(claimProperties.getSubject(),
                List.of(claimProperties.getRole()),
                Map.of("type", claimProperties.getType(),
                        "iss", claimProperties.getIssuer(),
                        "id", claimProperties.getId(),
                        "aud", claimProperties.getAudience())));
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
