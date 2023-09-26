package com.example.jwt.util.jwt.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.Cookie;

@Service
public class CookiesService {

    private static final Logger logger = LoggerFactory.getLogger(CookiesService.class);

    public String getAccessTokenFromCookies(Cookie[] cookies) {
        
        
        if(cookies == null) {
            return null;
        }
        System.out.println(1);
        for (Cookie cookie : cookies) {
            System.out.println("cookie: " + cookie.getValue());
            if ("accessToken".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    
    }

    public String getRefreshTokenFromCookies(Cookie[] cookies) {
        if(cookies == null)
            return null;
        
        for(Cookie cookie: cookies)
            if("refreshToken".equals(cookie.getName()))
                return cookie.getValue();

        return null;
    }
}