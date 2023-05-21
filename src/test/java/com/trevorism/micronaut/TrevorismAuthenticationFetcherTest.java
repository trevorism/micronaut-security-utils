package com.trevorism.micronaut;

import com.trevorism.SigningKeyException;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.simple.SimpleHttpRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class TrevorismAuthenticationFetcherTest {

    @Test
    void testFetchAuthentication() {
        TrevorismAuthenticationFetcher trevorismAuthenticationFetcher = new TrevorismAuthenticationFetcher();
        SimpleHttpRequest<String> simpleHttpRequest = new SimpleHttpRequest<>(HttpMethod.GET, "/", "");
        String token = "ey...";
        simpleHttpRequest.header("Authorization", "bearer " + token);

        assertThrows(SigningKeyException.class, () -> trevorismAuthenticationFetcher.fetchAuthentication(simpleHttpRequest));
    }
}
