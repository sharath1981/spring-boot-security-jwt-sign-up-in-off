package com.svh.springbootsecurityjwt.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.svh.springbootsecurityjwt.constant.AppConstants;
import com.svh.springbootsecurityjwt.util.JwtUtil;

import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Log4j2
@RequiredArgsConstructor
@Component
public class AppUserLogoutHandler implements LogoutHandler {

    private final CacheManager cacheManager;
    private final JwtUtil jwtUtil;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.info("LOGGED OUT...");
        jwtUtil.getJwtFromRequest(request)
                .ifPresent(jwt -> cacheManager.getCache(AppConstants.BLACKLISTED_JWT).put(jwt, jwt));
    }
}
