package com.example.jwt.controller.auth;

import com.example.jwt.dto.request.auth.AuthenticationRequest;
import com.example.jwt.dto.request.auth.RegisterRequest;
import com.example.jwt.dto.response.auth.AuthenticationTokenResponse;
import com.example.jwt.error.ErrorResponse;
import com.example.jwt.service.auth.AuthenticationService;
import com.example.jwt.type.i.auth.AuthenticateInterface;
import com.example.jwt.type.i.auth.LogoutInterface;
import com.example.jwt.type.i.auth.RefreshTokenInterface;
import com.example.jwt.type.i.auth.RegisterInterface;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;
    @PostMapping("/register")
    public ResponseEntity<RegisterInterface> register(@RequestBody RegisterRequest request, HttpServletResponse response) {
        return service.register(request, response);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticateInterface> authenticate(@RequestBody AuthenticationRequest request, HttpServletResponse response) {
        return service.authenticate(request, response);
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutInterface> logout(HttpServletRequest request, HttpServletResponse response) {
        return service.logout(request, response);
    }

    @PostMapping("/getAccessToken")
    public ResponseEntity<RefreshTokenInterface> getAccessToken(HttpServletRequest request, HttpServletResponse response) {
        return service.getAccessToken(request, response);
    }
}
