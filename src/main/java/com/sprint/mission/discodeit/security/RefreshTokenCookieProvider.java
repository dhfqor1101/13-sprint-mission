package com.sprint.mission.discodeit.security;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class RefreshTokenCookieProvider {

    private static final String SAME_SITE = "Lax";
    private static final String PATH = "/";

    private final Duration refreshTokenExpiration;

    public RefreshTokenCookieProvider(
            @Value("${discodeit.jwt.refresh-token-expiration}")
            Duration refreshTokenExpiration
    ) {
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public ResponseCookie create(
            String refreshToken,
            boolean secure
    ) {
        return ResponseCookie
                .from(
                        JwtTokenProvider.REFRESH_TOKEN_COOKIE_NAME,
                        refreshToken
                )
                .httpOnly(true)
                .secure(secure)
                .sameSite(SAME_SITE)
                .path(PATH)
                .maxAge(refreshTokenExpiration)
                .build();
    }

    public ResponseCookie delete(boolean secure) {
        return ResponseCookie
                .from(
                        JwtTokenProvider.REFRESH_TOKEN_COOKIE_NAME,
                        ""
                )
                .httpOnly(true)
                .secure(secure)
                .sameSite(SAME_SITE)
                .path(PATH)
                .maxAge(Duration.ZERO)
                .build();
    }
}