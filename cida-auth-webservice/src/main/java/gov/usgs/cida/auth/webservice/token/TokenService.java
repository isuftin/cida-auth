package gov.usgs.cida.auth.webservice.token;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.util.AuthTokenFactory;
import java.util.Calendar;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author isuftin
 */
@Path("/")
public class TokenService {
	private final static Logger LOG = LoggerFactory.getLogger(TokenService.class);
	private final static String ONE_DAY_IN_SECONDS_PARAM = "86400";
	/**
	 *
	 * @param tokenId
	 * @return
	 */
	@GET
	@Path("{tokenId}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getToken(@PathParam("tokenId") @DefaultValue("no token provided")String tokenId) {
		LOG.trace("Attempting to retrieve token {}", tokenId);
		Response response;
		AuthTokenDAO dao = new AuthTokenDAO();
		AuthToken token = dao.getByTokenId(tokenId);
		
		if (token != null) {
			response = Response.ok(token.toJSON(), MediaType.APPLICATION_JSON_TYPE).build();
		} else {
			response = Response.status(Response.Status.NOT_FOUND).build();
		}
		
		return response;
	}
	
	@PUT
	@Path("/extend/{tokenId}/{seconds}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response extendToken(
			@PathParam("tokenId") @DefaultValue("no token provided") String tokenId,
			@PathParam("seconds") int seconds) {
		LOG.trace("Attempting to extent token {}", tokenId);
		Response response;
		AuthTokenDAO dao = new AuthTokenDAO();
		AuthToken token = dao.getByTokenId(tokenId);
		
		if (token != null) {
			token.extendExpiration(seconds);
			int updated = dao.updateTokenExpiration(token);
			if (updated == 0) {
				response = Response.serverError().build();
			} else {
				response = Response.ok(token.toJSON(), MediaType.APPLICATION_JSON_TYPE).build();
			}
		} else {
			response = Response.status(Response.Status.NOT_FOUND).build();
		}
		
		return response;
	}
}
