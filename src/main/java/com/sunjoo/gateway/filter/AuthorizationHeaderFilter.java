package com.sunjoo.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    @Value("${jwt.secret}")
    private String secret;

    private static final String USERNO_CLAIM = "userNo";
    private Long userNo;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return orError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorization = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            log.info("authorization : " + authorization);
            String jwt = authorization.replace("Bearer ", "");
            log.info("replace bearer jwt : " + jwt);

            if(!isJwtValid(jwt)) {
                return orError(exchange, "Invalid JWT token", HttpStatus.UNAUTHORIZED);
            }

            log.info("login user no : " + userNo);

            request.mutate().header("userNo", String.valueOf(userNo)).build();
            return chain.filter(exchange);
        };
    }

    private boolean isJwtValid(String jwt) {
        boolean valid = false;

        try {
            userNo = JWT.require(Algorithm.HMAC512(secret)).build().verify(jwt).getClaim(USERNO_CLAIM)
                    .asLong();
            valid = true;
        } catch (Exception e) {
            log.error("JWT validation failed : " + e.getMessage());
            valid = false;
        }

        return valid;
    }

    private Mono<Void> orError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(err);
        return response.setComplete();
    }
}
