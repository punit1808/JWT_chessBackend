
package com.chessmaster.Config;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.chessmaster.jwt.JwtService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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

        // Create secure HTTP-only cookie
        Cookie jwtCookie = new Cookie("jwt", token);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(true); // Required for SameSite=None
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(24 * 60 * 60);
        // jwtCookie.setDomain("localhost"); // Optional for dev
        // jwtCookie.setAttribute("SameSite", "None"); // Add this line if possible (Servlet 6 or newer)
        response.addCookie(jwtCookie);


        // Redirect to frontend without token in URL
        response.sendRedirect("http://localhost:3000/");
    }
}

