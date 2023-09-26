package com.example.jwt.service.token;

import com.example.jwt.env.expiration.ExpirationEnv;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    ExpirationEnv expirationEnv;

    public TokenService() {
        this.expirationEnv = new ExpirationEnv();
    }

    public String getAccessTokenSetHeader(String token) {
        return ResponseCookie.from("accessToken", token)
                // .domain("localhost")
                .path("/")
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .build()
                .toString();
    }

    public String getRefreshTokenSetHeader(String token) {
        return ResponseCookie.from("refreshToken", token)
                // .domain("localhost")
                .path("/")
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .build()
                .toString();
    }

    public String deleteAccessTokenSetHeader(String token) {
        return ResponseCookie.from("accessToken", token)
                // .domain("localhost")
                .path("/")
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .maxAge(0)
                .build()
                .toString();
    }

    public String deleteRefreshTokenSetHeader(String token) {
        return ResponseCookie.from("refreshToken", token)
                // .domain("localhost")
                .path("/")
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .maxAge(0)
                .build()
                .toString();
    }

}
