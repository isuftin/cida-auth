package gov.usgs.cida.auth.ws.rs.filter;

import gov.usgs.cida.auth.client.IAuthClient;
import gov.usgs.cida.auth.ws.rs.service.SecurityContextUtils;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
public abstract class AbstractTokenBasedSecurityFilter implements ContainerRequestFilter {
	private static final Logger LOG = LoggerFactory.getLogger(AbstractTokenBasedSecurityFilter.class);
	
	
	@Context private HttpServletRequest httpRequest;
	
	/**
	 * You must implement this method to provide the type of IAuthClient you want.
	 * {@link gov.usgs.cida.auth.client.IAuthClient}
	 * @return an implementation of IAuthClient
	 */
	public abstract IAuthClient getAuthClient();
	
	/**
	 * You must implement this method to provide additional roles you wish to grant to
	 * the authenticated user in addition to the roles associated with the token from the 
	 * authorization services
	 * 
	 * @return list
	 */
	public abstract List<String> getAdditionalRoles();
	
	/**
	 * Implementing classes must specify which roles are required for the token to be valid.
	 */
	public abstract List<String> getAuthorizedRoles();
	

	/**
	 * Implementing classes must specify which URIs do not require authentication
	 */
	public abstract List<String> getUnsecuredUris();
	
    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
    	//if root documentation or authenticate url, continue on without authorization
    	String requestedUri = requestContext.getUriInfo().getPath();
    	List<String> allowedUris = getUnsecuredUris();
    	if(allowedUris == null || !allowedUris.contains(requestedUri)) {
	        if (!SecurityContextUtils.isSessionOrSecurityContextAuthorizedForRoles(requestContext, httpRequest, getAuthorizedRoles())
	        		&& !SecurityContextUtils.isTokenAuthorized(requestContext, httpRequest, getAuthClient(), getAdditionalRoles())) {
	        	blockUnauthorizedRequest(requestContext);
	        }
    	}
    }
    
    private void blockUnauthorizedRequest(ContainerRequestContext requestContext) {
    	LOG.debug("Authentication failed");
    	requestContext.abortWith(Response
	            .status(Response.Status.UNAUTHORIZED)
	            .entity("User cannot access the resource.")
	            .build());
    }
}