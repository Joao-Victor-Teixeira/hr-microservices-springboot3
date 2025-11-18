package com.joaodev.hr_oauth.config.custom;

import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public class OAuth2ResourceOwnerPasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private static final long serialVersionUID = 1L;

    private final String username;
    private final String password;
    private final Set<String> scopes;

    public OAuth2ResourceOwnerPasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType,
			Authentication clientPrincipal, @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(authorizationGrantType, clientPrincipal, additionalParameters);
		this.username = (String) additionalParameters.get("username");
		this.password = (String) additionalParameters.get("password");
		this.scopes = scopes;
	}

    public String getUsername() {
		return this.username;
	}

	public String getPassword() {
		return this.password;
	}

	public Set<String> getScopes() {
		return this.scopes;
	}
}
