package gov.usgs.cida.auth.ws.rs.service;

import gov.usgs.cida.auth.client.IAuthClient;
import gov.usgs.cida.auth.utils.HttpTokenUtils;
import gov.usgs.cida.auth.ws.rs.AuthSecurityContext;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;

public class SecurityContextUtils {
	/**
	 * Will check the token attatched to the request context. If it is good, the security context will
	 * be updated with the allowed roles, and true will be returned.
	 * @param requestContext
	 * @param httpRequest
	 * @param client
	 * @param additionalRoles if token is valid, these are additional roles to add to the security context
	 * @return
	 */
	public static boolean isTokenAuthorized(ContainerRequestContext requestContext, HttpServletRequest httpRequest, IAuthClient client, List<String> additionalRoles) {
		boolean authenticated = false;
		authenticated = HttpTokenUtils.isTokenAuthorized(httpRequest, client, additionalRoles);

		if(authenticated) {//token is good, populate securitycontext and update browser session
			String tokenId = HttpTokenUtils.getTokenFromRequest(httpRequest);
			populateSecurityContext(requestContext, httpRequest, client, tokenId, additionalRoles);
			HttpTokenUtils.saveTokenToSession(httpRequest, tokenId);
		}
		return authenticated;
	}

	/**
	 * Will load the roles for the given token, append the given additional roles, and save that to the SecurityContext.
	 */
	public static void populateSecurityContext(ContainerRequestContext requestContext, HttpServletRequest httpRequest, IAuthClient client, String tokenId, List<String> additionalRoles) {
		List<String> roles = client.getRolesByToken(tokenId);
		if(additionalRoles != null) {
			roles.addAll(additionalRoles);
		}

		populateSecurityContext(requestContext, httpRequest, tokenId, roles);
	}

	/**
	 * Will load the token stored in the session and use it to load roles for the security context.
	 */
	public static void populateSecurityContextFromSession(ContainerRequestContext requestContext, HttpServletRequest httpRequest, IAuthClient client) {
		String tokenId = HttpTokenUtils.getTokenFromPreauthorizedSession(httpRequest);
		List<String> roles = client.getRolesByToken(tokenId);
		populateSecurityContext(requestContext, httpRequest, tokenId, roles);
	}

	/**
	 * Will load the roles for the given token, append the given additional roles, and save that to the SecurityContext.
	 */
	public static void populateSecurityContext(ContainerRequestContext requestContext, HttpServletRequest httpRequest, String tokenId, List<String> roles) {
		//set security context with role
		requestContext.setSecurityContext(
				new AuthSecurityContext(tokenId, roles));
	}

	/**
	 * Returns any previously authorized token associated with the http session.
	 * @param requestContext
	 * @param httpRequest
	 * @param roles
	 * @return
	 */
	public static String getAuthorizedSessionToken(HttpServletRequest httpRequest) {
		return HttpTokenUtils.getTokenFromPreauthorizedSession(httpRequest);
	}
}
