package gov.usgs.cida.auth.webservice.authentication;

import gov.usgs.cida.auth.model.AuthToken;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path(ActiveDirectoryService.AUTHENTICATION_PATH)
public class ActiveDirectoryService {

	public static final String AUTHENTICATION_PATH = "ad";
	private final static Logger LOGGER = LoggerFactory.getLogger(ActiveDirectoryService.class);

	@POST
	@Path("/token")
	@Consumes("application/x-www-form-urlencoded")
	@Produces(MediaType.APPLICATION_JSON)
	public Response authenticate(@FormParam("username") String username, @FormParam("password") String password) {
		Response response;
		AuthToken token = new AuthToken();
		return null;
	}
}
