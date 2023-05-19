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

public class TrevorismCorrelationFilterTest {

    @Test
    void getOrder() {
        TrevorismCorrelationFilter trevorismCorrelationFilter = new TrevorismCorrelationFilter();

        assertEquals(0, trevorismCorrelationFilter.getOrder());
    }

    @Test
    void testDoFilter() {
        TrevorismCorrelationFilter trevorismCorrelationFilter = new TrevorismCorrelationFilter();
        Publisher<MutableHttpResponse<?>> mutableHttpResponsePublisher = trevorismCorrelationFilter.doFilter(
                new SimpleHttpRequest<String>(HttpMethod.GET, "/", ""),
                request -> Mono.just(SimpleHttpResponseFactory.INSTANCE.ok()));

        mutableHttpResponsePublisher.subscribe(new Subscriber<MutableHttpResponse<?>>() {
            @Override
            public void onSubscribe(Subscription s) {
                s.request(1);
            }

            @Override
            public void onNext(MutableHttpResponse<?> mutableHttpResponse) {
                assertEquals(200, mutableHttpResponse.getStatus().getCode());
            }

            @Override
            public void onError(Throwable t) {
                fail(t);
            }

            @Override
            public void onComplete() {

            }
        });
    }


}