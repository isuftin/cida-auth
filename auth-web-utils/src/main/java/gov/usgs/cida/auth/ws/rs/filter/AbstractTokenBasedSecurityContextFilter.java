package gov.usgs.cida.auth.ws.rs.filter;

import gov.usgs.cida.auth.client.IAuthClient;
import gov.usgs.cida.auth.ws.rs.service.SecurityContextUtils;

import java.io.IOException;
import java.util.List;

import javax.annotation.Priority;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Context;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
/**
 * This jersey filter automatically handles checking a token and/or session for valid authentication status.
 * It then populates teh security context with the user roles associated with a token. This filter will NOT
 * restrict access.
 * 
 * @author thongsav
 */
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public abstract class AbstractTokenBasedSecurityContextFilter implements ContainerRequestFilter {
	private static final Logger LOG = LoggerFactory.getLogger(AbstractTokenBasedSecurityContextFilter.class);
	
	
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
	
    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
    	//The two calls below DO populate the security context with the roles needed. They also update the session.
        boolean sessionAuthorized = SecurityContextUtils.isSessionOrSecurityContextAuthorizedForRoles(requestContext, httpRequest, getAuthorizedRoles());
        boolean tokenAuthorized = SecurityContextUtils.isTokenAuthorized(requestContext, httpRequest, getAuthClient(), getAdditionalRoles());
        
        LOG.trace("Session authorized: {}", sessionAuthorized);
        LOG.trace("Token authorized: {}", tokenAuthorized);
    }
}