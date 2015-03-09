package gov.usgs.cida.auth.ws.rs.service;

import gov.usgs.cida.auth.client.IAuthClient;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.utils.HttpTokenUtils;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthTokenService {
	private static final Logger LOG = LoggerFactory.getLogger(AuthTokenService.class);

	private List<String> additionalRolesGranted;
	private IAuthClient client;
	
	public AuthTokenService(IAuthClient client, List<String> additionalRolesGranted) {
		this.additionalRolesGranted = additionalRolesGranted;
		this.client = client;
	}
	
	public Response getToken(
			String username, 
			String password, 
			ContainerRequestContext requestContext, 
			HttpServletRequest httpRequest) {
		
		AuthToken token = null;
		Response response;
		
		try {
			token = client.getNewToken(username, password);
			
			String tokenId = token.getTokenId();

			if (StringUtils.isNotBlank(tokenId)) {
				response = Response.ok(token.toJSON(), MediaType.APPLICATION_JSON_TYPE).build();
				SecurityContextUtils.populateSecurityContext(requestContext, httpRequest, client, tokenId, additionalRolesGranted);
				HttpTokenUtils.saveTokenToSession(httpRequest, tokenId);
				HttpTokenUtils.saveUsernameToSession(httpRequest, token);
			} else {
				LOG.warn("Failed to authenticate " + username);
				response = Response.status(Response.Status.UNAUTHORIZED).build();
			}
		} catch(NotAuthorizedException ex) {
			response = Response.status(Response.Status.UNAUTHORIZED).build();
		}

		return response;
	}

	public Response logout(ContainerRequestContext requestContext, HttpServletRequest httpRequest) {
		String token = HttpTokenUtils.getTokenFromHeader(httpRequest.getHeader(HttpTokenUtils.AUTHORIZATION_HEADER));
		if(token == null) {
			token = HttpTokenUtils.getTokenFromPreauthorizedSession(httpRequest);
		}
		boolean invalidated = false;
		if(token != null) {
			invalidated = client.invalidateToken(token);
		}
		requestContext.setSecurityContext(null);
		httpRequest.getSession().invalidate();
		return Response.ok("{ \"status\": \"" + (invalidated ? "success" : "failed") + "\"}", MediaType.APPLICATION_JSON_TYPE).build();
	}
}
