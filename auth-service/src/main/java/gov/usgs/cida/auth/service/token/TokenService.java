package gov.usgs.cida.auth.service.token;

import java.util.List;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.dao.IAuthTokenDAO;
import gov.usgs.cida.auth.exception.ExpiredTokenException;
import gov.usgs.cida.auth.model.AuthToken;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenService implements ITokenService {
	private final static Logger LOG = LoggerFactory.getLogger(TokenService.class);
	
	IAuthTokenDAO tokenDao;
	
	public TokenService() {
		this.tokenDao = new AuthTokenDAO();
	}
	
	//for testing
	/* (non-Javadoc)
	 * @see gov.usgs.cida.auth.service.token.ITokenService#setTokenDao(gov.usgs.cida.auth.dao.IAuthTokenDAO)
	 */
	@Override
	public void setTokenDao(IAuthTokenDAO tokenDao) {
		this.tokenDao = tokenDao;
	}
	public TokenService(IAuthTokenDAO tokenDao) {
		this.tokenDao = tokenDao;
	}
	
	/* (non-Javadoc)
	 * @see gov.usgs.cida.auth.service.token.ITokenService#getTokenById(java.lang.String)
	 */
	@Override
	public AuthToken getTokenById(String tokenId) {
		AuthToken token = null;
		
		if (StringUtils.isNotBlank(tokenId)) {
			token = tokenDao.getByTokenById(tokenId);
		}

		if (token != null) {
			LOG.trace("Token {} retrieved", tokenId);
			if (token.isExpired()) {
				LOG.info("Token {} expired, will be deleted", tokenId);
				tokenDao.deleteTokenUsingId(tokenId);
				token = null;
			} else {
				try {
					token.updateLastAccess();
					token.extendExpiration();
					tokenDao.updateToken(token);
				} catch (Exception e) {
					LOG.warn("Could not update last access for token {}", tokenId);
					LOG.warn("Exception: ", e);
				}
			}
		}
		return token;
	}
	
	/* (non-Javadoc)
	 * @see gov.usgs.cida.auth.service.token.ITokenService#getRolesByTokenId(java.lang.String)
	 */
	@Override
	public List<String> getRolesByTokenId(String tokenId) {
		AuthToken token = new TokenService().getTokenById(tokenId);
		return token.getRoles();
	}
	
	/* (non-Javadoc)
	 * @see gov.usgs.cida.auth.service.token.ITokenService#deleteToken(java.lang.String)
	 */
	@Override
	public int deleteToken(String tokenId) {
		return tokenDao.deleteTokenUsingId(tokenId);
	}
	
	/* (non-Javadoc)
	 * @see gov.usgs.cida.auth.service.token.ITokenService#tokenExists(java.lang.String)
	 */
	@Override
	public boolean tokenExists(String tokenId) {
		return tokenDao.exists(tokenId);
	}
	
	/* (non-Javadoc)
	 * @see gov.usgs.cida.auth.service.token.ITokenService#validateToken(java.lang.String)
	 */
	@Override
	public void validateToken(String tokenId) throws ExpiredTokenException {
		if(!isTokenValid(tokenId)) {
			throw new ExpiredTokenException("Token is expired or does not exist.");
		}
	}
	
	private boolean isTokenValid(String tokenId) {
		IAuthTokenDAO dao = tokenDao;
		return dao.exists(tokenId) && !dao.getByTokenById(tokenId).isExpired();
	}
}
