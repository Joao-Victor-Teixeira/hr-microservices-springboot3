package com.joaodev.hr_oauth.config.custom;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

public class OAuth2ResourceOwnerPasswordAuthenticationConverter implements AuthenticationConverter {

	public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

	@Override
	public Authentication convert(HttpServletRequest request) {
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		
		if (!PASSWORD.getValue().equals(grantType)) {
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
		MultiValueMap<String, String> parameters = getParameters(request);

		String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
		if (!StringUtils.hasText(username) || parameters.get(OAuth2ParameterNames.USERNAME).size() != 1) {
			throw new IllegalArgumentException("Invalid username parameter"); 
		}

		String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
		if (!StringUtils.hasText(password) || parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
			throw new IllegalArgumentException("Invalid password parameter");
		}

		Set<String> requestedScopes = null;
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope)) {
			requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		Map<String, Object> additionalParameters = parameters.entrySet().stream()
				.filter(e -> !e.getKey().equals(OAuth2ParameterNames.GRANT_TYPE) &&
						!e.getKey().equals(OAuth2ParameterNames.SCOPE))
				.collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get(0)));

		return new OAuth2ResourceOwnerPasswordAuthenticationToken(PASSWORD, clientPrincipal, requestedScopes, additionalParameters);
	}

	private MultiValueMap<String, String> getParameters(HttpServletRequest request) {
		Map<String, String[]> parameterMap = request.getParameterMap();
		MultiValueMap<String, String> parameters = new org.springframework.util.LinkedMultiValueMap<>(parameterMap.size());
		parameterMap.forEach((key, values) -> {
			for (String value : values) {
				parameters.add(key, value);
			}
		});
		return parameters;
	}
}