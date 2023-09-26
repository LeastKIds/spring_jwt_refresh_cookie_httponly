package com.example.jwt.util.jwt;

import com.example.jwt.util.jwt.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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
            .cors(cors -> cors.configurationSource(securityCorsConfigurationSource()))
            // .cors(withDefaults())
            .cors(cors -> cors.disable())
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

    @Bean
    public WebMvcConfigurer corsConfigurationSource() {
        return new WebMvcConfigurer() {
            public void addCorsMappings(CorsRegistry registry) {
                registry
                    .addMapping("/**")
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowedOrigins("https://localhost:3000", "http://localhost:3000")
                    .allowCredentials(true);
            }
        };
    }

     @Bean
    public CorsConfigurationSource securityCorsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("https://localhost:3000", "http://localhost:3000"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // @Bean
	// CorsConfigurationSource corsConfigurationSourceTest() {
	// 	CorsConfiguration configuration = new CorsConfiguration();
	// 	configuration.setAllowedOrigins(Arrays.asList("https://localhost:3000"));
	// 	configuration.setAllowedMethods(Arrays.asList("GET","POST"));
	// 	UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	// 	source.registerCorsConfiguration("/**", configuration);
	// 	return source;
	// }
  
}
