package com.trevorism.micronaut;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.http.simple.SimpleHttpResponseFactory;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.*;

public class TrevorismHstsFilterTest {

    @Test
    void getOrder() {
        TrevorismHstsFilter trevorismHstsFilter = new TrevorismHstsFilter();

        assertEquals(1, trevorismHstsFilter.getOrder());
    }

    @Test
    void testDoFilter() throws InterruptedException {
        TrevorismHstsFilter trevorismHstsFilter = new TrevorismHstsFilter();
        Publisher<MutableHttpResponse<?>> mutableHttpResponsePublisher = trevorismHstsFilter.doFilter(
                new SimpleHttpRequest<String>(HttpMethod.GET, "/", ""),
                request -> Mono.just(SimpleHttpResponseFactory.INSTANCE.ok()));

        mutableHttpResponsePublisher.subscribe(new Subscriber<>() {
            @Override
            public void onSubscribe(Subscription s) {
                s.request(50);
            }

            @Override
            public void onNext(MutableHttpResponse<?> mutableHttpResponse) {
                assertEquals("max-age=-1; includeSubDomains; preload", mutableHttpResponse.getHeaders().get("Strict-Transport-Security"));
            }

            @Override
            public void onError(Throwable t) {
            }

            @Override
            public void onComplete() {
            }
        });

        Thread.sleep(1000);
    }


}