package gov.usgs.cida.auth.ws.rs.service;

import gov.usgs.cida.auth.client.IAuthClient;
import gov.usgs.cida.auth.utils.HttpTokenUtils;
import gov.usgs.cida.auth.ws.rs.AuthSecurityContext;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.SecurityContext;

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
    	authenticated = HttpTokenUtils.isTokenInHeaderAuthorized(httpRequest, client, additionalRoles);
    	
    	String tokenId = HttpTokenUtils.getTokenFromHeader(httpRequest.getHeader(HttpTokenUtils.AUTHORIZATION_HEADER));
    	
    	if(authenticated) {//token is good, populate securitycontext and update browser session
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
		
		//set security context with role
		requestContext.setSecurityContext(
				new AuthSecurityContext(tokenId, roles));
    }
    
	/**
	 * Will check the HttpServletRequest for the existence of a preauthorized session, if no preauthorized session is present
	 * check the SecurityContext for a user that has one of the roles. 
	 * 
	 * @param requestContext
	 * @param httpRequest
	 * @param roles list of roles that token is to be checked against
	 * @return returns true if the token has one of hte roles
	 */
    public static boolean isSessionOrSecurityContextAuthorizedForRoles(ContainerRequestContext requestContext, HttpServletRequest httpRequest, List<String> roles) {

    	boolean authenticated = HttpTokenUtils.isSessionPreauthorized(httpRequest);
    	
    	if(!authenticated) {
	        final SecurityContext securityContext =
	                    requestContext.getSecurityContext();
	        
	        if (securityContext != null) {
	        	for(String r : roles) {
	        		if(securityContext.isUserInRole(r)) {
	        			authenticated = true;
	        		}
	        	}
	        }
        }
        
        return authenticated;
    }
}
