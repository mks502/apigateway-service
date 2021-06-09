package com.mks.apigatewayservice.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotEmpty;

@Data
@Component
@ConfigurationProperties(prefix = "token")
public class JwtProperties {

    @NotEmpty
    private long expirationTime;

    @NotEmpty
    private String secretKey;

    @NotEmpty
    private long logoutTokenExpirationTime;
}
