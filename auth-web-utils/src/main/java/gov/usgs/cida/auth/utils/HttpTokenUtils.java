package gov.usgs.cida.auth.utils;

import gov.usgs.cida.auth.client.IAuthClient;
import gov.usgs.cida.auth.model.AuthToken;

import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

public class HttpTokenUtils {
	public static final String AUTHORIZED_TOKEN_SESSION_ATTRIBUTE = "AuthorizedToken";
	public static final String AUTHORIZED_USER_SESSION_ATTRIBUTE = "AuthorizedUser";
	public static final String AUTH_BEARER_STRING = "Bearer";
	public static final String AUTHORIZATION_HEADER = "Authorization";

	/**
	 * Pulls token in the "Authorization" HTTP header. The token
	 * should be of format "Bearer the-auth-token-string" which follows a pattern set by OAUTH2.
	 * 
	 * @param httpRequest
	 * @return
	 */
	private static String getTokenFromHeader(String authHeader) {
		String token = null;

		if(authHeader != null &&
				authHeader.toLowerCase().startsWith(AUTH_BEARER_STRING.toLowerCase() + " ")) {
			token = authHeader;
			token = token.replaceAll(AUTH_BEARER_STRING + "\\s+", "");
			token = token.replaceAll(AUTH_BEARER_STRING.toLowerCase() + "\\s+", "");
			token = token.replaceAll(AUTH_BEARER_STRING.toUpperCase() + "\\s+", "");
		}

		return token;
	}
	
	/**
	 * Given a HttpServletRequest, will look for the auth token in the header first, then check the session
	 * for a preauthorized token (usually put in place my an authorization filter before the request).
	 * 
	 * @param req
	 * @return the auth token used to previously this request.
	 */
	public static String getTokenFromRequest(final HttpServletRequest req) {
		String authToken = HttpTokenUtils.getTokenFromHeader(req.getHeader(HttpTokenUtils.AUTHORIZATION_HEADER));
		if(authToken == null) {
			authToken = (String) req.getSession().getAttribute(HttpTokenUtils.AUTHORIZED_TOKEN_SESSION_ATTRIBUTE);
		}
		return authToken;
	}

	/**
	 * Will check the token in the Authorization header of the request OR session, returns true if its valid. 
	 * Will also save the header to the session if authorized.
	 * 
	 * @param httpRequest
	 * @param client
	 * @param additionalRoles if token is valid, these are additional roles to add to the security context
	 * @return
	 */
	public static boolean isTokenAuthorized(HttpServletRequest httpRequest, IAuthClient client, List<String> additionalRoles) {
		boolean authenticated = false;
		String tokenId = validateTokenFormat(HttpTokenUtils.getTokenFromRequest(httpRequest));
		
		authenticated = client.isValidToken(tokenId);

		if(authenticated) {
			saveTokenToSession(httpRequest, tokenId);
			saveUsernameToSession(httpRequest, client.getToken(tokenId));
		}

		return authenticated;
	}

	public static void saveTokenToSession(HttpServletRequest httpRequest, String tokenId) {
		httpRequest.getSession().setAttribute(AUTHORIZED_TOKEN_SESSION_ATTRIBUTE, validateTokenFormat(tokenId));
	}
	
	public static void saveUsernameToSession(HttpServletRequest httpRequest, AuthToken token) {
		httpRequest.getSession().setAttribute(AUTHORIZED_USER_SESSION_ATTRIBUTE, token.getUsername());
	}

	public static String validateTokenFormat(String rawTokenId) {
		try {
			UUID.fromString(rawTokenId);
			return rawTokenId;
		} catch (Exception ex) {
			return null;
		}
	}
}
