package com.example.jwt.util.jwt.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_refresh")
public class RefreshToken {

    @Id
    @GeneratedValue
    private Long id;

    @NotBlank(message = "token is not blank")
    private String token;

    // 왜인지 모르겠는데 NotBlank를 쓰면 에러가 나옴
    private Date expirationTime;

    @NotBlank(message = "userEmail is not blank")
    private String userEmail;
}
