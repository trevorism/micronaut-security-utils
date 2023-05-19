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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.UUID;

@Filter("/**")
class TrevorismCorrelationFilter implements HttpServerFilter {

    public static String CORRELATION_ID_HEADER_KEY = "X-Correlation-ID";
    private static final Logger log = LoggerFactory.getLogger( TrevorismCorrelationFilter.class.getName() );
    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        String correlationId = getOrCreateCorrelationId(request);
        log.info("Correlation ID: " + correlationId);

        Publisher<MutableHttpResponse<?>> publisher = chain.proceed(request);
        return Publishers.then(publisher, httpResponse -> {
            httpResponse.headers(Map.of(CORRELATION_ID_HEADER_KEY, correlationId));
        });
    }

    private static String getOrCreateCorrelationId(HttpRequest<?> request) {
        String correlationId = request.getHeaders().get(CORRELATION_ID_HEADER_KEY);
        if(correlationId == null){
            correlationId = UUID.randomUUID().toString();
        }
        return correlationId;
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
        return 0;
    }
}