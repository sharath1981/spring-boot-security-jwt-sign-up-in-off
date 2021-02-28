package com.svh.springbootsecurityjwt.controller;

import java.util.Optional;

import com.svh.springbootsecurityjwt.dto.AuthRequest;
import com.svh.springbootsecurityjwt.service.AppUserService;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class AppUserController {
    private final AppUserService appUserService;

    @PostMapping("sign-up")
    public void signUp(@RequestBody AuthRequest authRequest) {
        Optional.ofNullable(authRequest).ifPresent(appUserService::save);
    }

}
