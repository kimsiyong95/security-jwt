package com.jwt.securityjwt.jwt;

public interface JwtProperties {
    String SECRET = "kimsiyong"; // 우리 서버만 알고 있는 비밀값
    int EXPIRATION_MINUTE = 10; // 10일 (1/1000초)
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
