package com.example.jwt.service.auth;

import com.example.jwt.env.expiration.ExpirationEnv;
import com.example.jwt.error.ErrorResponse;
import com.example.jwt.service.token.TokenService;
import com.example.jwt.type.i.auth.RegisterInterface;
import com.example.jwt.util.jwt.filter.JwtAuthenticationFilter;
import com.example.jwt.util.jwt.service.JwtService;
import com.example.jwt.util.jwt.domain.RefreshToken;
import com.example.jwt.util.jwt.type.RefreshTokenRepository;
import com.example.jwt.dto.request.auth.AuthenticationRequest;
import com.example.jwt.dto.request.auth.RegisterRequest;
import com.example.jwt.dto.response.auth.AuthenticationTokenResponse;
import com.example.jwt.dto.response.auth.LogoutResponse;
import com.example.jwt.util.redis.RedisService;
import com.example.jwt.type.i.auth.LogoutInterface;
import com.example.jwt.type.i.auth.RefreshTokenInterface;
import com.example.jwt.type.e.user.Role;
import com.example.jwt.domain.auth.User;
import com.example.jwt.repository.auth.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletResponse;

import jakarta.validation.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Set;

import static com.example.jwt.util.AES.AESUtil.decrypt;
import static com.example.jwt.util.AES.AESUtil.encrypt;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;
    private final RedisService redisService;

    private final TokenService tokenService;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);


    // validation
    @Autowired
    private Validator validator;


    @Transactional
    public ResponseEntity<RegisterInterface> register(RegisterRequest request, HttpServletResponse response) {


        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.User)
                .build();

//        Set<ConstraintViolation<User>> violations = validator.validate(user);
//        if (!violations.isEmpty()) {
//            StringBuilder sb = new StringBuilder();
//            for (ConstraintViolation<User> violation : violations) {
//                sb.append(violation.getMessage()).append("\n");
//            }
//            throw new ValidationException(sb.toString());
//        }


        repository.save(user);
        var jwtToken = jwtService.generateToken(user);

        // Refresh Token
        var refreshToken = jwtService.generateRefreshToken(user);

        AuthenticationTokenResponse tokenResponse =
                AuthenticationTokenResponse.builder()
                        .firstname(user.getFirstname())
                        .lastname(user.getLastname())
                        .email(user.getEmail())
                        .role(user.getRole())
                        .build();


        response.addHeader("Set-Cookie", tokenService.getAccessTokenSetHeader(jwtToken));
        response.addHeader("Set-Cookie", tokenService.getRefreshTokenSetHeader(refreshToken));


        return ResponseEntity.ok(tokenResponse);
    }


    // 로그인 역할
    @Transactional(readOnly=true)
    public ResponseEntity<AuthenticationTokenResponse> authenticate(AuthenticationRequest request, HttpServletResponse response) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                ));
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);

        // Refresh Token
        var refreshToken = jwtService.generateRefreshToken(user);


        response.addHeader("Set-Cookie", tokenService.getAccessTokenSetHeader(jwtToken));
        response.addHeader("Set-Cookie", tokenService.getRefreshTokenSetHeader(refreshToken));

        return ResponseEntity.ok(
                AuthenticationTokenResponse
                        .builder()
                        .firstname(user.getFirstname())
                        .lastname(user.getLastname())
                        .email(user.getEmail())
                        .role(user.getRole())
                        .build()
        );


    }

    @Transactional
    public ResponseEntity<LogoutInterface> logout(String accessToken, String refreshToken) throws RuntimeException{

        if(!accessToken.startsWith("Bearer ") || !refreshToken.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("Invalid token format").build()
            );
        }
        String accessJwt = accessToken.substring(7);
        String refreshJwt = refreshToken.substring(7);

        String userEmail;
        try {
            userEmail = jwtService.extractRefreshTokenUsername(refreshJwt);
        } catch (ExpiredJwtException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("The token is expired").build()
            );
        } catch (JwtException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("The token is invalid").build()
            );
        }

        if(refreshTokenRepository.findByToken(encrypt(refreshJwt)).isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("This refresh token is not in the storage").build()
            );
        }



        RefreshToken reToken = refreshTokenRepository.findByToken(encrypt(refreshJwt)).get();
        refreshTokenRepository.delete(reToken);

        Date expirationDate = jwtService.extractExpiration(accessJwt);
        Date currentDate = new Date();
        long differenceInMilliseconds = expirationDate.getTime() - currentDate.getTime();
        if (differenceInMilliseconds < 0) {
            // This means the token has already expired.
            differenceInMilliseconds = 0;
        }

        redisService.setBlackList(encrypt(accessJwt), userEmail, differenceInMilliseconds);
        return ResponseEntity.ok(LogoutResponse.builder().status(true).build());

    }

    @Transactional
    public ResponseEntity<RefreshTokenInterface> getAccessToken(String refreshToken, HttpServletResponse response) {
        // 헤더에 jwt토큰임을 알리는 Bearer가 앞에 존재하는지
        if(!refreshToken.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("Invalid token format").build()
            );
        }
        // Bearer을 제거한 순수 토큰
        String jwt = refreshToken.substring(7);

        String userEmail;
        try {
            userEmail = jwtService.extractRefreshTokenUsername(jwt);
        } catch (ExpiredJwtException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("The token is expired").build()
            );
        } catch (JwtException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("The token is invalid").build()
            );
        }

        var refresh = refreshTokenRepository.findByUserEmail(userEmail);
        if(refresh.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("This user does not possess a token.").build()
            );
        }
        if(jwt.equals(decrypt(refresh.get().getToken()))) {
            var user = repository.findByEmail(userEmail)
                    .orElseThrow();
            var accessToken = jwtService.generateToken(user);
            var reGenerateRefreshToken = jwtService.generateRefreshToken(user);

            response.addHeader("Set-Cookie", tokenService.getAccessTokenSetHeader(accessToken));
            response.addHeader("Set-Cookie", tokenService.getRefreshTokenSetHeader(reGenerateRefreshToken));

            return ResponseEntity.ok(
                    AuthenticationTokenResponse
                            .builder()
                            .firstname(user.getFirstname())
                            .lastname(user.getLastname())
                            .email(user.getEmail())
                            .role(user.getRole())
                            .build()
            );
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    ErrorResponse.builder().error("The token values do not match.").build()
            );
        }
    }

}
