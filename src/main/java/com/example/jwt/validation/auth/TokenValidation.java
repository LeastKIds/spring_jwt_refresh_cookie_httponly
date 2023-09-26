package com.example.jwt.validation.auth;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.jwt.error.ErrorResponse;
import com.example.jwt.util.jwt.type.RefreshTokenRepository;
import static com.example.jwt.util.AES.AESUtil.encrypt;

public class TokenValidation {
    
    private static final Logger logger = LoggerFactory.getLogger(TokenValidation.class);

    public ErrorResponse expiredToken() {
        Map<String, String> errors = new HashMap<>();
        errors.put("token_expired", "The token is expired");
        logger.error(String.format("The token is expired"));

        return ErrorResponse.builder().errors(errors).build();
    }

    public ErrorResponse invalidToken() {
        Map<String, String> errors = new HashMap<>();
        errors.put("token_invalid", "The token is invalid");
        logger.error(String.format("The token is invalid"));

        return ErrorResponse.builder().errors(errors).build();
    }

    public ErrorResponse findByToken(String refreshJwt, RefreshTokenRepository refreshTokenRepository) {
        Map<String, String> errors = new HashMap<>();

        if(refreshTokenRepository.findByToken(encrypt(refreshJwt)).isEmpty()) {
            errors.put("refreshToken_notFound","The refresh token could not be found in the database.");
            logger.error("The refresh token could not be found in the database.");
        }

        return ErrorResponse.builder().errors(errors).build();
    }

    public ErrorResponse notFoundEmail() {
        Map<String, String> errors = new HashMap<>();
        errors.put("email_notFound", "The user cannot be found");
        logger.error(String.format("The user cannot be found"));

        return ErrorResponse.builder().errors(errors).build();

    }

    public ErrorResponse notEqulasToken() {
        Map<String, String> errors = new HashMap<>();
        errors.put("token_notEqulas", "The token values do not match.");
        logger.error(String.format("The token values do not match."));

        return ErrorResponse.builder().errors(errors).build();
    }
}
