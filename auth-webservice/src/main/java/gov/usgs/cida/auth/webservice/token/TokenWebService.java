package gov.usgs.cida.auth.webservice.token;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.service.ServicePaths;
import gov.usgs.cida.auth.service.token.ITokenService;
import gov.usgs.cida.auth.service.token.TokenService;

import java.util.List;

import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.HEAD;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

/**
 *
 * @author isuftin
 */
@Path("/")
public class TokenWebService {
	private final static Logger LOG = LoggerFactory.getLogger(TokenWebService.class);
	
	ITokenService tokenService = new TokenService();

	/**
	 *
	 * @param tokenId
	 * @return
	 */
	@GET
	@Path("{tokenId}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getToken(@PathParam("tokenId") @DefaultValue("") String tokenId) {
		tokenService.validateToken(tokenId);
		LOG.trace("Attempting to retrieve token by id '{}'", tokenId);
		return getTokenResponse(tokenId);
	}
	
	/**
	 *
	 * @param tokenId
	 * @return
	 */
	@GET
	@Path("{tokenId}/" + ServicePaths.ROLES)
	@Produces(MediaType.APPLICATION_JSON)
	public Response getRolesByToken(@PathParam("tokenId") @DefaultValue("") String tokenId) {
		tokenService.validateToken(tokenId);
		LOG.trace("Attempting to retrieve roles for token '{}'", tokenId);
		Response response;
		List<String> roles = tokenService.getRolesByTokenId(tokenId);
		response = Response.ok(new Gson().toJson(roles), MediaType.APPLICATION_JSON_TYPE).build();
		return response;
	}
	
	@DELETE
	@Path("{tokenId}")
	public Response invalidateToken(@PathParam("tokenId") @DefaultValue("") String tokenId) {
		tokenService.validateToken(tokenId);
		LOG.trace("Attempting to delete token by id '{}'", tokenId);
		return getInvalidateTokenResponse(tokenId);
	}
	
	@HEAD
	@Path("{tokenId}")
	public Response checkToken(@PathParam("tokenId") @DefaultValue("") String tokenId) {
		tokenService.validateToken(tokenId);
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
		int deleted = tokenService.deleteToken(tokenId);
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
		AuthToken token = new TokenService().getTokenById(tokenId);

		if (token != null) {
			response = Response.ok(token.toJSON(), MediaType.APPLICATION_JSON_TYPE).build();
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
		if (tokenService.tokenExists(tokenId)) {
			response = Response.ok().build();
		} else {
			response = Response.status(Response.Status.NOT_FOUND).build();
		}
		return response;
	}
}
