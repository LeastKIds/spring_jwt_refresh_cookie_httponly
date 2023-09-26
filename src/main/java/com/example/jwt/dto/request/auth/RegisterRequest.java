package com.example.jwt.dto.request.auth;

import com.example.jwt.type.i.auth.RegisterInterface;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest implements RegisterInterface {

    
    private String firstname;
   
    private String lastname;

  
    private String email;
   
    private String password;
}
