package com.mks.apigatewayservice.filter;

import com.mks.apigatewayservice.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    private final JwtProperties jwtProperties;

    public AuthorizationHeaderFilter(JwtProperties jwtProperties) {
        super(Config.class);
        this.jwtProperties = jwtProperties;
    }


    //login -> token -> users (with token) -> header (include token)
    @Override
    public GatewayFilter apply(Config config) {
        //Pre Filter
        return ((exchange, chain) -> {
            //사용자가 요청했던 정보에서 Header의 token을 전달받음
            ServerHttpRequest request = exchange.getRequest();

            if(!request.getHeaders().containsKey("X-AUTH-TOKEN")){
                return onError(exchange, "authorization header not exist", HttpStatus.UNAUTHORIZED);
            }

            String jwt = request.getHeaders().get("X-AUTH-TOKEN").get(0);

            if(!isValidateToken(jwt)){
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        });
    }

    // 토큰의 유효성 + 만료일자 확인
    public boolean isValidateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(jwtProperties.getSecretKey()).parseClaimsJws(token);
            return isNotExpired(claims);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isNotExpired(Jws<Claims> claims) {
        return !claims.getBody().getExpiration().before(new Date());
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(errorMessage);

        byte[] bytes = errorMessage.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);

        return response.writeWith(Flux.just(buffer));
    }

    //설정 관련 전담
    public static class Config {

    }
}
