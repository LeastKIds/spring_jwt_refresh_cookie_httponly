package com.example.jwt.util.redis;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "spring.data.redis")
@Data
public class RedisProperties {

    private int port;
    private String host;

    public int getPort() {
        return this.port;
    }

    public String getHost() {
        return this.host;
    }
}