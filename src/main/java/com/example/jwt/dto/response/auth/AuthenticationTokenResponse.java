package com.example.jwt.dto.response.auth;

import com.example.jwt.type.e.user.Role;
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
public class AuthenticationTokenResponse implements RefreshTokenInterface, RegisterInterface {

    @NotBlank(message = "firstname is not blank")
    private String firstname;
    @NotBlank(message = "lastname is not blank")
    private String lastname;
    @NotBlank(message = "email is not blank")
    private String email;
    @NotBlank(message = "role is not blank")
    private Role role;
}
