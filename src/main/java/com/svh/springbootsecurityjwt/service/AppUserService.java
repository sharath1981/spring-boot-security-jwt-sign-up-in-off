package com.svh.springbootsecurityjwt.service;

import java.util.Optional;

import com.svh.springbootsecurityjwt.domain.AppUser;
import com.svh.springbootsecurityjwt.domain.RoleName;
import com.svh.springbootsecurityjwt.dto.AuthRequest;
import com.svh.springbootsecurityjwt.repository.AppUserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class AppUserService {
    private final AppUserRepository appUserRepository;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;

    public AppUser save(AuthRequest authRequest) {
        return Optional.ofNullable(authRequest)
                       .map(this::createAppUser)
                       .map(appUserRepository::save)
                       .orElseThrow();
    }

    private AppUser createAppUser(AuthRequest request) {
        final var appUser = new AppUser();
        appUser.setUsername(request.getUsername());
        appUser.setPassword(passwordEncoder.encode(request.getPassword()));
        appUser.setAccountNonExpired(Boolean.TRUE);
        appUser.setAccountNonLocked(Boolean.TRUE);
        appUser.setCredentialsNonExpired(Boolean.TRUE);
        appUser.setEnabled(Boolean.TRUE);
       
        roleService.findByAuthority(RoleName.ROLE_USER)
                   .ifPresent(appUser.getRoles()::add);
        return appUser;
    }
}
