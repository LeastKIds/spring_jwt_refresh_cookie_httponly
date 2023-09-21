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
                .path("/")
                .secure(true)
                .sameSite("Lax")
                .httpOnly(true)
                .build()
                .toString();
    }

    public String getRefreshTokenSetHeader(String token) {
        return ResponseCookie.from("refreshToken", token)
                .path("/")
                .secure(true)
                .sameSite("Lax")
                .httpOnly(true)
                .build()
                .toString();
    }

}
