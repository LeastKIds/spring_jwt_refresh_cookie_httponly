package com.example.jwt.util.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisTemplate<String, Object> redisBlackListTemplate;


    public void setBlackList(String token, String userEmail, long seconds) {
        // HashMap을 생성하여 토큰과 유저의 이메일을 저장
        HashMap<String, String> map = new HashMap<>();
        map.put("token", token);
        map.put("userEmail", userEmail);

        // Redis에 토큰 값을 키로 하여 HashMap 값을 저장
        redisBlackListTemplate.opsForHash().putAll(token, map);

        // 해당 토큰 값을 키로 가진 Hash에 만료 시간 설정
        redisBlackListTemplate.expire(token, seconds, TimeUnit.MILLISECONDS);
    }
    public boolean hasKeyBlackList(String key) {
        return Boolean.TRUE.equals(redisBlackListTemplate.hasKey(key));
    }
}
