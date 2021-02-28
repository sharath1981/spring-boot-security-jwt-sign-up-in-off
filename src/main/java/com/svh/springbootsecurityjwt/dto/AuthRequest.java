package com.svh.springbootsecurityjwt.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public final class AuthRequest {
    private String username;
    private String password;
}
