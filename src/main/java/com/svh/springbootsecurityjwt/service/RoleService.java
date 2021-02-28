package com.svh.springbootsecurityjwt.service;

import java.util.Optional;

import com.svh.springbootsecurityjwt.domain.Role;
import com.svh.springbootsecurityjwt.domain.RoleName;
import com.svh.springbootsecurityjwt.repository.RoleRepository;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class RoleService {
    private final RoleRepository roleRepository;

	public Optional<Role> findByAuthority(RoleName authority) {
        return roleRepository.findByAuthority(authority);
	}

}
