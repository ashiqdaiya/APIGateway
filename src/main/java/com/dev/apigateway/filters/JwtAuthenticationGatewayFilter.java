package com.dev.apigateway.filters;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationGatewayFilter extends AbstractGatewayFilterFactory<JwtAuthenticationGatewayFilter.Config> {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    public JwtAuthenticationGatewayFilter(JwtAuthenticationFilter jwtAuthenticationFilter) {
        super(Config.class);
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            return jwtAuthenticationFilter.filter(exchange, new WebFilterChainAdapter(chain));
        };
    }

    public static class Config {
        // Put the configuration properties here if needed
    }

    private static class WebFilterChainAdapter implements WebFilterChain {
        private final GatewayFilterChain gatewayFilterChain;

        WebFilterChainAdapter(GatewayFilterChain gatewayFilterChain) {
            this.gatewayFilterChain = gatewayFilterChain;
        }

//        @Override
//        public Mono<Void> filter(ServerWebExchange exchange) {
//            return gatewayFilterChain.filter(exchange);
//        }

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            return gatewayFilterChain.filter(exchange);
        }
    }
}
