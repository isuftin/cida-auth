package gov.usgs.cida.auth.webservice.authentication;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;
import gov.usgs.cida.auth.service.ServicePaths;
import gov.usgs.cida.auth.service.authentication.LDAPService;

import javax.naming.NamingException;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path(ServicePaths.AD)
public class ActiveDirectoryService {

	private final static Logger LOG = LoggerFactory.getLogger(ActiveDirectoryService.class);

	@POST
	@Path(ServicePaths.TOKEN)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doAuth(
			@FormParam("username") String username,
			@FormParam("password")
			@DefaultValue("") String password) throws NamingException {
		LOG.trace("User {} is attempting to authenticate", username);
		return getResponse(username, password.toCharArray());
	}

	/**
	 * Authenticates, creates token, generates proper Response
	 *
	 * @param username
	 * @param password
	 * @return
	 */
	protected Response getResponse(String username, char[] password) {
		Response response;
		User user = LDAPService.authenticate(username, password);

		if (user.isAuthenticated()) {
			AuthTokenDAO authTokenDAO = new AuthTokenDAO();
			user.setRoles(authTokenDAO.getSyncopeRoles(username));
			LOG.debug("User {} has authenticated", user.getUsername());
			AuthToken token = authTokenDAO.create(user);

			if (token != null) {
				LOG.trace("Added token {} to database", token.getTokenId());
				response = Response.ok(token.toJSON(), MediaType.APPLICATION_JSON_TYPE).build();
			} else {
				LOG.warn("Unable to add token to database");
				response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
			}
		} else {
			LOG.debug("User {} could not authenticate", username);
			response = Response.status(Response.Status.UNAUTHORIZED).build();
		}
		return response;
	}
}
