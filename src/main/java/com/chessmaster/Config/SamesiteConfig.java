package com.chessmaster.Config;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.springframework.boot.web.embedded.tomcat.TomcatContextCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SamesiteConfig {

    @Bean
    public TomcatContextCustomizer sameSiteCookieConfig() {
        return context -> {
            Rfc6265CookieProcessor processor = new Rfc6265CookieProcessor();
            processor.setSameSiteCookies("None"); // 👈 necessary for cross-origin
            context.setCookieProcessor(processor);
        };
    }
}
