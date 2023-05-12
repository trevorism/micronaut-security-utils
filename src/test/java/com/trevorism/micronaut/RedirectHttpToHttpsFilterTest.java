package com.trevorism.micronaut;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.http.simple.SimpleHttpResponseFactory;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.*;

class RedirectHttpToHttpsFilterTest {

    @Test
    void getOrder() {
        RedirectHttpToHttpsFilter filter = new RedirectHttpToHttpsFilter();
        assertEquals(Integer.MIN_VALUE, filter.getOrder());
    }

    @Test
    void testFilter() throws InterruptedException{
        RedirectHttpToHttpsFilter filter = new RedirectHttpToHttpsFilter();
        Publisher<MutableHttpResponse<?>> mutableHttpResponsePublisher = filter.doFilter(
                new SimpleHttpRequest<>(HttpMethod.GET, "/", ""),
                request -> Mono.just(SimpleHttpResponseFactory.INSTANCE.ok()));

        mutableHttpResponsePublisher.subscribe(new Subscriber<>() {
            @Override
            public void onSubscribe(Subscription s) {
                s.request(50);
            }

            @Override
            public void onNext(MutableHttpResponse<?> mutableHttpResponse) {
                assertEquals(HttpStatus.PERMANENT_REDIRECT, mutableHttpResponse.getStatus());
                assertEquals("https:/", mutableHttpResponse.getHeaders().get("Location"));
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