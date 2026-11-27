package com.trevorism.micronaut;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;
import reactor.test.StepVerifier;

import java.lang.reflect.Field;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrevorismAuthenticationFetcherTest {

    private static final String SIGNING_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private static final String OTHER_SIGNING_KEY = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

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

    @Test
    void testMalformedBearerTokenIsAnonymousAndLoggedAtDebugWithoutStackTrace() throws Exception {
        assertRejectedQuietly(withAuthorizationHeader("bearer garbage"));
    }

    @Test
    void testMalformedSessionCookieIsAnonymousAndLoggedAtDebugWithoutStackTrace() throws Exception {
        SimpleHttpRequest<String> request = new SimpleHttpRequest<>(HttpMethod.GET, "/", "");
        request.cookie(Cookie.of("session", "garbage"));
        assertRejectedQuietly(request);
    }

    @Test
    void testEmptyBearerTokenIsAnonymousAndLoggedAtDebugWithoutStackTrace() throws Exception {
        assertRejectedQuietly(withAuthorizationHeader("bearer "));
    }

    @Test
    void testExpiredTokenIsAnonymousAndLoggedAtDebugWithoutStackTrace() throws Exception {
        String expiredToken = createToken(Map.of("role", "admin"), SIGNING_KEY, Instant.now().minusSeconds(3600));
        assertRejectedQuietly(withAuthorizationHeader("bearer " + expiredToken));
    }

    @Test
    void testTokenSignedWithAnotherKeyIsAnonymousAndLoggedAtDebugWithoutStackTrace() throws Exception {
        String forgedToken = createToken(Map.of("role", "admin"), OTHER_SIGNING_KEY, Instant.now().plusSeconds(300));
        assertRejectedQuietly(withAuthorizationHeader("bearer " + forgedToken));
    }

    @Test
    void testMissingSigningKeyIsStillLoggedAtWarn() {
        List<ILoggingEvent> events = captureLogs(() -> {
            SimpleHttpRequest<String> request = new SimpleHttpRequest<>(HttpMethod.GET, "/", "");
            request.header("Authorization", "bearer garbage");
            StepVerifier.create(new TrevorismAuthenticationFetcher().fetchAuthentication(request)).expectComplete().verify();
        });

        assertTrue(events.stream().anyMatch(event -> event.getLevel() == Level.WARN));
    }

    private void assertRejectedQuietly(SimpleHttpRequest<String> request) throws Exception {
        TrevorismAuthenticationFetcher fetcher = createFetcher();

        List<ILoggingEvent> events = captureLogs(() ->
                StepVerifier.create(fetcher.fetchAuthentication(request)).expectComplete().verify());

        assertEquals(1, events.size());
        assertEquals(Level.DEBUG, events.get(0).getLevel());
        assertNull(events.get(0).getThrowableProxy());
    }

    private static List<ILoggingEvent> captureLogs(Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(TrevorismAuthenticationFetcher.class.getName());
        Level originalLevel = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.DEBUG);
        try {
            action.run();
            return List.copyOf(appender.list);
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(originalLevel);
        }
    }

    private static SimpleHttpRequest<String> withAuthorizationHeader(String value) {
        SimpleHttpRequest<String> request = new SimpleHttpRequest<>(HttpMethod.GET, "/", "");
        request.header("Authorization", value);
        return request;
    }

    private Publisher<Authentication> fetchWithClaims(Map<String, ?> claims) throws Exception {
        String token = createToken(claims, SIGNING_KEY, Instant.now().plusSeconds(300));
        return createFetcher().fetchAuthentication(withAuthorizationHeader("bearer " + token));
    }

    private static TrevorismAuthenticationFetcher createFetcher() throws Exception {
        TrevorismAuthenticationFetcher fetcher = new TrevorismAuthenticationFetcher();
        Field field = TrevorismAuthenticationFetcher.class.getDeclaredField("propertiesProvider");
        field.setAccessible(true);
        field.set(fetcher, new StubPropertiesBean());
        return fetcher;
    }

    private static String createToken(Map<String, ?> claims, String signingKey, Instant expiration) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey));
        return Jwts.builder()
                .subject("me@trevorism.com")
                .issuer("https://trevorism.com")
                .issuedAt(Date.from(expiration.minusSeconds(600)))
                .expiration(Date.from(expiration))
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
