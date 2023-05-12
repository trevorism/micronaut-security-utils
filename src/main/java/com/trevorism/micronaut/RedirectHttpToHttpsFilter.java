package com.trevorism.micronaut;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.FilterChain;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.net.URI;

import static io.micronaut.http.HttpResponse.permanentRedirect;

@Filter("/**")
public class RedirectHttpToHttpsFilter implements HttpServerFilter {

    @Override
    public int getOrder() {
        return HIGHEST_PRECEDENCE;
    }

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        if (request.isSecure()) {
            return chain.proceed(request);
        }
        return publishRedirect(request.getUri());
    }

    @Override
    public Publisher<? extends HttpResponse<?>> doFilter(HttpRequest<?> request, FilterChain chain) {
        if (request.isSecure()) {
            return chain.proceed(request);
        }
        return publishRedirect(request.getUri());
    }

    private static Mono<MutableHttpResponse<?>> publishRedirect(URI request) {
        URI currentUri = request;
        try {
            URI redirectUri = new URI(
                    "https",
                    null,
                    currentUri.getHost(),
                    currentUri.getPort(),
                    currentUri.getPath(),
                    currentUri.getQuery(),
                    currentUri.getFragment()
            );
            return Mono.just(permanentRedirect(redirectUri));
        } catch (Exception e) {
            return Mono.error(e);
        }
    }


}