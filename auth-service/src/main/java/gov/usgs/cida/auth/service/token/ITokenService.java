package gov.usgs.cida.auth.service.token;

import gov.usgs.cida.auth.dao.IAuthTokenDAO;
import gov.usgs.cida.auth.exception.ExpiredTokenException;
import gov.usgs.cida.auth.model.AuthToken;

import java.util.List;

public interface ITokenService {

	//for testing
	public void setTokenDao(IAuthTokenDAO tokenDao);

	public AuthToken getTokenById(String tokenId);

	public List<String> getRolesByTokenId(String tokenId);

	/**
	 * Deletes a token based on a token ID
	 * 
	 * @param tokenId
	 * @return 
	 */
	public int deleteToken(String tokenId);

	public boolean tokenExists(String tokenId);

	public void validateToken(String tokenId)
			throws ExpiredTokenException;

}