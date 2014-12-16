package gov.usgs.cida.auth.ws.rs.service;

import java.util.List;

import gov.usgs.cida.auth.client.IAuthClient;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("auth")
public abstract class AbstractAuthTokenService {
	private static final Logger LOG = LoggerFactory.getLogger(AbstractAuthTokenService.class);

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
	
	private AuthTokenService service;
	
	private AuthTokenService getService() {
		if(service == null) {
			LOG.debug("service being initialized with roles " + getAdditionalRoles().toArray());
			service = new AuthTokenService(getAuthClient(), getAdditionalRoles());
		}
		return service;
	}
	
	@POST
	@Path("authenticate")
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response getToken(
			@FormParam("username") String username, 
			@FormParam("password") String password, 
			@Context ContainerRequestContext requestContext, 
			@Context HttpServletRequest httpRequest) {
		return getService().getToken(username, password, requestContext, httpRequest);
	}

	@POST
	@Path("/logout")
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response logout(@Context ContainerRequestContext requestContext, @Context HttpServletRequest httpRequest) {
		return getService().logout(requestContext, httpRequest);
	}
}
