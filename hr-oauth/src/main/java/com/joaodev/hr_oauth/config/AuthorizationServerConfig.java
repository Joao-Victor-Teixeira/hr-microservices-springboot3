package com.joaodev.hr_oauth.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class AuthorizationServerConfig {

    // Estas são as "credenciais do aplicativo" (Postman/Frontend)
    // O Nélio vai colocar isto no application.properties
    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;

    // --- OS BEANS ESSENCIAIS DA "FÁBRICA" ---

    /**
     * 1. O Filtro de Segurança do próprio Authorization Server
     * (Define a página de login, etc.)
     */
    @Bean
    @Order(1) // Ordem de prioridade
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults()); // Habilita OpenID Connect
        
        // Aceita o token de acesso (Bearer Token)
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    /**
     * 2. O "Cadastro de Clientes"
     * (Quem tem permissão de pedir tokens?)
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        // O "Cliente" (nosso frontend ou Postman)
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId) // O ID que o Nélio vai usar
            .clientSecret(passwordEncoder.encode(clientSecret)) // A Senha (tem que ser com BCrypt)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.PASSWORD) // O fluxo "password" que o Nélio usa
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .scope(OidcScopes.OPENID)
            .scope("read")
            .scope("write")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
            .build();

        // Por enquanto, guardamos o cliente em memória
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 3. A "Chave Secreta" para assinar os Tokens (JWT)
     * (O "Selo Holográfico")
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * 4. O Decodificador de JWT (para ler os tokens)
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 5. Onde o servidor "mora" (configurações)
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}
