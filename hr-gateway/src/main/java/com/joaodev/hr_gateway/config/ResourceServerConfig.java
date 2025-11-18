package com.joaodev.hr_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
public class ResourceServerConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http){
        http.csrf(csrf -> csrf.disable())
        .authorizeExchange(exchanges -> exchanges
        .pathMatchers("/hr-oauth/oauth2/token").permitAll()
        .pathMatchers("/eureka/**").permitAll()
        .anyExchange().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        

        return http.build();
    }
}
