package com.example.jwt.util.jwt.type;

import com.example.jwt.util.jwt.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByUserEmail(String userEmail);
    Optional<RefreshToken> findByToken(String token);
}
