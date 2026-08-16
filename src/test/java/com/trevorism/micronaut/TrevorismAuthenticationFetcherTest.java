package com.trevorism.micronaut;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.test.StepVerifier;

import java.lang.reflect.Field;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrevorismAuthenticationFetcherTest {

    private static final String SIGNING_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    @Test
    void testFetchAuthentication() {
        TrevorismAuthenticationFetcher trevorismAuthenticationFetcher = new TrevorismAuthenticationFetcher();
        SimpleHttpRequest<String> simpleHttpRequest = new SimpleHttpRequest<>(HttpMethod.GET, "/", "");
        String token = "ey...";
        simpleHttpRequest.header("Authorization", "bearer " + token);

        Publisher<Authentication> publisher = trevorismAuthenticationFetcher.fetchAuthentication(simpleHttpRequest);
        StepVerifier.create(publisher).expectComplete().verify();
    }

    @Test
    void testFetchAuthenticationWithRoleClaim() throws Exception {
        Publisher<Authentication> publisher = fetchWithClaims(Map.of("role", "user", "dbId", "123"));

        StepVerifier.create(publisher)
                .assertNext(authentication -> {
                    assertEquals("me@trevorism.com", authentication.getName());
                    assertEquals(1, authentication.getRoles().size());
                    assertTrue(authentication.getRoles().contains("user"));
                })
                .expectComplete()
                .verify();
    }

    @Test
    void testFetchAuthenticationWithoutRoleClaim() throws Exception {
        Publisher<Authentication> publisher = fetchWithClaims(Map.of("dbId", "123", "entityType", "refresh"));

        StepVerifier.create(publisher)
                .assertNext(authentication -> {
                    assertEquals("me@trevorism.com", authentication.getName());
                    assertTrue(authentication.getRoles().isEmpty());
                    assertEquals("refresh", authentication.getAttributes().get("type"));
                })
                .expectComplete()
                .verify();
    }

    private Publisher<Authentication> fetchWithClaims(Map<String, ?> claims) throws Exception {
        TrevorismAuthenticationFetcher fetcher = new TrevorismAuthenticationFetcher();
        Field field = TrevorismAuthenticationFetcher.class.getDeclaredField("propertiesProvider");
        field.setAccessible(true);
        field.set(fetcher, new StubPropertiesBean());

        SimpleHttpRequest<String> request = new SimpleHttpRequest<>(HttpMethod.GET, "/", "");
        request.header("Authorization", "bearer " + createToken(claims));
        return fetcher.fetchAuthentication(request);
    }

    private static String createToken(Map<String, ?> claims) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SIGNING_KEY));
        return Jwts.builder()
                .subject("me@trevorism.com")
                .issuer("https://trevorism.com")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(300)))
                .claims(claims)
                .signWith(key)
                .compact();
    }

    private static class StubPropertiesBean extends PropertiesBean {
        @Override
        public String getProperty(String prop) {
            return "signingKey".equals(prop) ? SIGNING_KEY : null;
        }
    }
}
