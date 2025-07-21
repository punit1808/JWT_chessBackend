
package com.chessmaster.Config;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.chessmaster.jwt.JwtService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

@Component
public class OAuthSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;

    public OAuthSuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        String token = jwtService.generateToken(email);

        // ✅ Create ResponseCookie with SameSite=None
        ResponseCookie jwtCookie = ResponseCookie.from("jwt", token)
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(24 * 60 * 60)
            .sameSite("None") // 🔥 Critical for cross-site cookies
            .build();

        // ✅ Add to response header
        response.setHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());

        // ✅ Redirect after setting cookie
        response.sendRedirect("https://jwt-chess-frontend.vercel.app/Start");
    }
}

