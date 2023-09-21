package com.example.jwt.util.jwt;

import com.example.jwt.util.jwt.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public DefaultSecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)  // csrf를 비활성화
            .authorizeHttpRequests((auth) ->
                    auth
                        .requestMatchers("/api/v1/auth/**")
                        .permitAll()  // 위의 요청은 모두 허용
                        .anyRequest()
                        .authenticated()  // 그 이외의 요청은 모두 인증된 사용자만
            )
            .sessionManagement((sessionManagement) ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 세션 유지 안 함
            )
            // 사용자 정의 인증 추가
            .authenticationProvider(authenticationProvider)
            // jwtAuthFilter를 UsernamePasswordAuthenticationFilter 전에 배치
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
