package com.trevorism.micronaut;

import com.trevorism.*;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import jakarta.inject.Inject;
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

    private static final Logger log = LoggerFactory.getLogger(TrevorismAuthenticationFetcher.class.getName());

    @Inject
    private PropertiesBean propertiesProvider;

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        try {
            String sessionToken = getTokenFromSessionCookie(request);
            String bearerToken = getTokenFromBearerToken(request);
            if (bearerToken == null && sessionToken == null) {
                return Mono.empty();
            }
            return Mono.just(publishToken(Objects.requireNonNullElse(bearerToken, sessionToken)));
        } catch (Exception e) {
            log.warn(SecurityConstants.Messages.TOKEN_REJECTED, e.getMessage());
            log.debug(SecurityConstants.Messages.TOKEN_REJECTION_DETAILS, e);
            return Mono.empty();
        }
    }

    private Authentication publishToken(String bearerToken) {
        ClaimProperties claimProperties = ClaimsProvider.getClaims(bearerToken, getSigningKey());
        Map<String, Object> claimMap = convertClaimsToMap(claimProperties);
        return Authentication.build(claimProperties.getSubject(), List.of(claimProperties.getRole()), claimMap);
    }

    private String getSigningKey() {
        try {
            String key = propertiesProvider.getProperty(SecurityConstants.Config.SIGNING_KEY);
            if(key == null || key.isBlank())
                throw new Exception();
            return key;
        } catch (Exception e) {
            throw new SigningKeyException();
        }
    }

    private String getTokenFromBearerToken(HttpRequest<?> request) {
        try {
            String authString = request.getHeaders().get(SecurityConstants.Http.AUTHORIZATION_HEADER);
            if (authString == null || !authString.toLowerCase().startsWith(SecurityConstants.Http.BEARER_PREFIX)) {
                return null;
            }
            return authString.substring(SecurityConstants.Http.BEARER_PREFIX.length());
        } catch (Exception ignored) {
            return null;
        }
    }

    private String getTokenFromSessionCookie(HttpRequest<?> request) {
        try {
            return request.getCookies().get(SecurityConstants.Http.SESSION_COOKIE).getValue();
        } catch (Exception ignored) {
            return null;
        }
    }

    private Map<String, Object> convertClaimsToMap(ClaimProperties claimProperties) {
        Map<String, Object> claimMap = new HashMap<>();
        addIfNotNull(claimMap, SecurityConstants.Claims.ISSUER, claimProperties.getIssuer());
        addIfNotNull(claimMap, SecurityConstants.Claims.AUDIENCE, claimProperties.getAudience());
        addIfNotNull(claimMap, SecurityConstants.Claims.SUBJECT, claimProperties.getSubject());
        addIfNotNull(claimMap, SecurityConstants.Claims.ID, claimProperties.getId());
        addIfNotNull(claimMap, SecurityConstants.Claims.TYPE, claimProperties.getType());
        addIfNotNull(claimMap, SecurityConstants.Claims.TENANT, claimProperties.getTenant());
        addIfNotNull(claimMap, SecurityConstants.Claims.PERMISSIONS, claimProperties.getPermissions());
        return claimMap;
    }

    private void addIfNotNull(Map<String, Object> claimMap, String key, Object value) {
        if(value != null) {
            claimMap.put(key, value);
        }
    }

    @Override
    public int getOrder() {
        return -1000;
    }
}
