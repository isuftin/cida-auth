package gov.usgs.cida.auth.service.token;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.model.AuthToken;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenService {
	private final static Logger LOG = LoggerFactory.getLogger(TokenService.class);
	
	public AuthToken getTokenById(String tokenId) {
		AuthTokenDAO dao = new AuthTokenDAO();
		AuthToken token = null;
		
		if (StringUtils.isNotBlank(tokenId)) {
			token = dao.getByTokenById(tokenId);
		}

		if (token != null) {
			LOG.trace("Token {} retrieved", tokenId);
			if (token.isExpired()) {
				LOG.info("Token {} expired, will be deleted", tokenId);
				dao.deleteTokenUsingId(tokenId);
				token = null;
			} else {
				try {
					token.updateLastAccess();
					token.extendExpiration();
					dao.updateToken(token);
				} catch (Exception e) {
					LOG.warn("Could not update last access for token {}", tokenId);
				}
			}
		}
		return token;
	}
}
