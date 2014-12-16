package gov.usgs.cida.auth.utils;

import gov.usgs.cida.auth.client.IAuthClient;
import gov.usgs.cida.auth.ws.rs.AuthSecurityContext;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.SecurityContext;

public class HttpTokenUtils {
	public static final String AUTHORIZED_TOKEN_SESSION_ATTRIBUTE = "AuthorizedToken";
	public static final String AUTH_BEARER_STRING = "Bearer";
	public static final String AUTHORIZATION_HEADER = "Authorization";

    public static String getTokenIdFromRequestContext(ContainerRequestContext requestContext) {
    	String authHeader = null;
    	MultivaluedMap<String,String> headers = requestContext.getHeaders();
    	List<String> authHeaderEntries = headers.get(AUTHORIZATION_HEADER);
    	if(authHeaderEntries != null && authHeaderEntries.size() > 0) {
    		authHeader = authHeaderEntries.get(0);
    	}
    	
    	return getTokenFromHeader(authHeader);
    }
    
	/**
	 * Pulls token in the "Authorization" HTTP header. The token
	 * should be of format "Bearer the-auth-token-string" which follows a pattern set by OAUTH2.
	 * 
	 * @param httpRequest
	 * @return
	 */
	public static String getTokenFromHeader(String authHeader) {
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
	 * Will check a ContainerRequestContext and/or HttpServletRequest against a given role. If the session 
	 * is authorized, will save the token into the http session and return true.
	 * @param requestContext
	 * @param httpRequest
	 * @param roles list of roles that token is to be checked against
	 * @return returns true if the token has one of hte roles
	 */
    public static boolean isSessionAuthorizedForRoles(ContainerRequestContext requestContext, HttpServletRequest httpRequest, List<String> roles) {
    	boolean authenticated = false;
        final SecurityContext securityContext =
                    requestContext.getSecurityContext();
        
        if (securityContext != null) {
        	for(String r : roles) {
        		if(securityContext.isUserInRole(r)) {
        			authenticated = true;
        		}
        	}
        }
        
        if(httpRequest.getSession().getAttribute(AUTHORIZED_TOKEN_SESSION_ATTRIBUTE) != null) {
        	authenticated = true;
        }
        
        if(authenticated) {
        	saveTokenToSession(httpRequest, (String) httpRequest.getSession().getAttribute(AUTHORIZED_TOKEN_SESSION_ATTRIBUTE));
        }
        
        return authenticated;
    }
    
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
    	
    	String tokenId = getTokenIdFromRequestContext(requestContext);
    	authenticated = client.isValidToken(tokenId);
    	
    	if(authenticated) {//token is good, update browser session if possible
    		populateSecurityContext(requestContext, client, tokenId, additionalRoles);
    	}
    	return authenticated;
    }
    
    /**
     * Will load the roles for the given token, append the given additional roles, and save that to the SecurityContext.
     */
    public static void populateSecurityContext(ContainerRequestContext requestContext, IAuthClient client, String tokenId, List<String> additionalRoles) {
		List<String> roles = client.getRolesByToken(tokenId);
		if(additionalRoles != null) {
			roles.addAll(additionalRoles);
		}
		
		//set security context with role
		requestContext.setSecurityContext(
				new AuthSecurityContext(tokenId, roles));
    }
    
    public static void saveTokenToSession(HttpServletRequest httpRequest, String tokenId) {
		httpRequest.getSession().setAttribute(AUTHORIZED_TOKEN_SESSION_ATTRIBUTE, tokenId);
    }
}
