package com.chessmaster.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class OAuthUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Since you use Google OAuth, we trust the email is valid
        return User.builder()
                .username(email)
                .password("") // No password needed; it's OAuth
                .roles("USER") // Assign a default role
                .build();
    }
}

