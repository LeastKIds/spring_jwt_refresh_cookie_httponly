package com.example.jwt.dto.response.auth;

import com.example.jwt.type.e.user.Role;
import com.example.jwt.type.i.auth.AuthenticateInterface;
import com.example.jwt.type.i.auth.RefreshTokenInterface;
import com.example.jwt.type.i.auth.RegisterInterface;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationTokenResponse implements RefreshTokenInterface, RegisterInterface, AuthenticateInterface {

   
    private String firstname;
    private String lastname;
    private String email;
    private Role role;
}
