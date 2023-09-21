package com.example.jwt.dto.response.auth;

import com.example.jwt.type.i.auth.RefreshTokenInterface;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse implements RefreshTokenInterface {
    private String token;
}
