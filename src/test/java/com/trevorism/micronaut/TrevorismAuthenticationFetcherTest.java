package com.trevorism.micronaut;

import com.trevorism.SigningKeyException;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.test.StepVerifier;

import java.util.concurrent.Flow;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class TrevorismAuthenticationFetcherTest {

    @Test
    void testFetchAuthentication() {
        TrevorismAuthenticationFetcher trevorismAuthenticationFetcher = new TrevorismAuthenticationFetcher();
        SimpleHttpRequest<String> simpleHttpRequest = new SimpleHttpRequest<>(HttpMethod.GET, "/", "");
        String token = "ey...";
        simpleHttpRequest.header("Authorization", "bearer " + token);

        Publisher<Authentication> publisher = trevorismAuthenticationFetcher.fetchAuthentication(simpleHttpRequest);
        StepVerifier.create(publisher).expectComplete().verify();
    }
}
