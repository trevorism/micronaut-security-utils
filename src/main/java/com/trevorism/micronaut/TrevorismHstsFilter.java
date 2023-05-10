package com.trevorism.micronaut;

import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.FilterChain;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import org.reactivestreams.Publisher;

import java.util.Map;

@Filter("/**")
class TrevorismHstsFilter implements HttpServerFilter {

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        Publisher<MutableHttpResponse<?>> publisher = chain.proceed(request);
        return Publishers.then(publisher, httpResponse -> {
            System.out.println("Here");
            httpResponse.headers(Map.of("Strict-Transport-Security","max-age=-1; includeSubDomains; preload"));
        });
    }

    @Override
    public Publisher<? extends HttpResponse<?>> doFilter(HttpRequest<?> request, FilterChain chain) {
        if(chain instanceof ServerFilterChain){
            return doFilter(request, (ServerFilterChain) chain);
        }
        return chain.proceed(request);
    }

    @Override
    public int getOrder() {
        return 1;
    }
}