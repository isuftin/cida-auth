package gov.usgs.cida.auth.webservice.token;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.model.AuthToken;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.HEAD;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author isuftin
 */
@Path("/")
public class TokenService {

	private final static Logger LOG = LoggerFactory.getLogger(TokenService.class);

	/**
	 *
	 * @param tokenId
	 * @return
	 */
	@GET
	@Path("{tokenId}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getToken(@PathParam("tokenId") @DefaultValue("") String tokenId) {
		LOG.trace("Attempting to retrieve token by id '{}'", tokenId);
		return getTokenResponse(tokenId);
	}
	
	@DELETE
	@Path("{tokenId}")
	public Response invalidateToken(@PathParam("tokenId") @DefaultValue("") String tokenId) {
		LOG.trace("Attempting to delete token by id '{}'", tokenId);
		return getInvalidateTokenResponse(tokenId);
	}
	
	@HEAD
	@Path("{tokenId}")
	public Response checkToken(@PathParam("tokenId") @DefaultValue("") String tokenId) {
		LOG.trace("Attempting to retrieve token by id '{}'", tokenId);
		return getCheckTokenResponse(tokenId);
	}
	
	/**
	 * Deletes a token based on a token ID
	 * 
	 * @param tokenId
	 * @return 
	 */
	protected Response getInvalidateTokenResponse(String tokenId) {
		int deleted = new AuthTokenDAO().deleteTokenUsingId(tokenId);
		if (deleted == 1) {
			LOG.trace("Deleted token by id '{}'", tokenId);
		} else {
			LOG.trace("Did not delete token by id '{}'", tokenId);
		}
		
		return Response.ok().build();
	}
	
	/**
	 * Using a tokenID, get a token
	 * @param tokenId
	 * @return 
	 */
	protected Response getTokenResponse(String tokenId) {
		Response response;
		AuthTokenDAO dao = new AuthTokenDAO();
		AuthToken token = null;
		
		if (StringUtils.isNotBlank(tokenId)) {
			token = dao.getByTokenId(tokenId);
		}

		if (token != null) {
			LOG.trace("Token {} retrieved", tokenId);
			if (token.isExpired()) {
				LOG.info("Token {} expired, will be deleted", tokenId);
				dao.deleteTokenUsingId(tokenId);
				response = Response.status(Response.Status.NOT_FOUND).build();
			} else {
				try {
					token.updateLastAccess();
					token.extendExpiration();
					dao.updateToken(token);
				} catch (Exception e) {
					LOG.warn("Could not update last access for token {}", tokenId);
				}

				response = Response.ok(token.toJSON(), MediaType.APPLICATION_JSON_TYPE).build();
			}
		} else {
			response = Response.status(Response.Status.NOT_FOUND).build();
		}

		return response;
	}

	/**
	 * Performs a cheap check against to see if a token by a given ID exists
	 * @param tokenId
	 * @return 
	 */
	private Response getCheckTokenResponse(String tokenId) {
		Response response;
		if (new AuthTokenDAO().exists(tokenId)) {
			response = Response.ok().build();
		} else {
			response = Response.status(Response.Status.NOT_FOUND).build();
		}
		return response;
	}
}
