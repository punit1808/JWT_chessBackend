package com.chessmaster.Config;
import com.chessmaster.jwt.JwtAuthFilter;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.Customizer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

import com.chessmaster.Config.OAuthSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final OAuthSuccessHandler successHandler;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, OAuthSuccessHandler successHandler) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.successHandler = successHandler;
    }



    @Bean
    public OAuth2AuthorizationRequestResolver customAuthorizationRequestResolver(ClientRegistrationRepository repo) {
        DefaultOAuth2AuthorizationRequestResolver resolver =
            new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization");

        resolver.setAuthorizationRequestCustomizer(builder ->
            builder.additionalParameters(params -> {
                params.put("prompt", "consent"); // or "select_account"
            })
        );
        return resolver;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
    .cors(Customizer.withDefaults()) // Enable CORS
    .csrf().disable() // (optional) if you're not using CSRF protection
    .authorizeHttpRequests()
        .requestMatchers("/logout", "/login/**", "/oauth2/**","wss/**").permitAll()
        .anyRequest().authenticated()
    .and()
    .oauth2Login()
    .successHandler(successHandler)
    .and()
    .logout()
        .logoutUrl("/logout")
        .logoutSuccessHandler((request, response, authentication) -> {
            ResponseCookie cookie = ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .path("/")
                .maxAge(0)
                .build();
            response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
            response.setStatus(HttpServletResponse.SC_OK);
        })
    .and()
            // ✅ Register your JWT filter before UsernamePasswordAuthenticationFilter
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
        
    }


    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOrigins("http://localhost:3000","https://jwt-chess-frontend.vercel.app")
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowCredentials(true)
                    .allowedHeaders("*")
                    .exposedHeaders("Set-Cookie"); // Important for cookies
            }
        };
    }

}
