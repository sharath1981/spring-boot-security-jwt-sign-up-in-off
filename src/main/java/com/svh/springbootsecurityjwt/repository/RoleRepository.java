package com.svh.springbootsecurityjwt.repository;

import java.util.Optional;

import com.svh.springbootsecurityjwt.domain.Role;
import com.svh.springbootsecurityjwt.domain.RoleName;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    @EntityGraph(attributePaths = {"users"})
    Optional<Role> findByAuthority(RoleName authority);
}
