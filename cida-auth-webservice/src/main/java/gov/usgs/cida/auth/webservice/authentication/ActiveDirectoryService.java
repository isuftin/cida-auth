package gov.usgs.cida.auth.webservice.authentication;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;
import gov.usgs.cida.auth.service.authentication.LDAPService;
import gov.usgs.cida.auth.util.AuthTokenFactory;
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

@Path("ad")
public class ActiveDirectoryService {
	private final static Logger LOG = LoggerFactory.getLogger(ActiveDirectoryService.class);

	@POST
	@Path("/token")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response authenticate(
			@FormParam("username") String username, 
			@FormParam("password") 
			@DefaultValue("")  String password) throws NamingException {
		LOG.trace("User {} is attempting to authenticate", username);
		
		Response response;
		User user = LDAPService.authenticate(username, password.toCharArray());
		
		if (user.isAuthenticated()) {
			LOG.debug("User {} has authenticated", username);
			AuthToken token = AuthTokenFactory.create(username);
			AuthTokenDAO dao = new AuthTokenDAO();
			String tokenId = token.getTokenId();
			
			if (dao.insertToken(token) == 1) {
				LOG.trace("Added token {} to database", tokenId);
				token = dao.getByTokenId(token.getTokenId());
				if (token != null) {
					response = Response.ok(token.toJSON(), MediaType.APPLICATION_JSON_TYPE).build();
				} else {
					LOG.warn("Could not retrieve token {} from database", tokenId);
					response = Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
				}
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
