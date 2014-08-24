package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.lang3.StringUtils;

/**
 * An auth client with an internal map of tokens. Using this class will attempt
 * to cut down on traffic between the client and server when possible
 *
 * @author isuftin
 */
public class CachingAuthClient extends AuthClient {

	private static final Map<String, AuthToken> tokenMap = new ConcurrentHashMap<>();

	public CachingAuthClient(String authEndpoint) throws URISyntaxException {
		super(authEndpoint);
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public AuthToken getNewToken(String username, String password) {
		AuthToken token = super.getNewToken(username, password);
		if (token != null) {
			tokenMap.put(token.getTokenId(), token);
		}
		return token;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public AuthToken getToken(String tokenId) {
		AuthToken token;
		if (tokenMap.containsKey(tokenId)) {
			token = tokenMap.get(tokenId);
		} else {
			token = super.getToken(tokenId);
		}

		if (token != null && !super.isValidToken(token)) {
			invalidateToken(token);
			token = null;
		}

		return token;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean isValidToken(String tokenId) {
		boolean isValid = false;
		if (StringUtils.isNotBlank(tokenId)) {
			if (tokenMap.containsKey(tokenId)) {
				isValid = isValidToken(tokenMap.get(tokenId));
			} else {
				AuthToken token = getToken(tokenId);
				if (token != null) {
					isValid = isValidToken(token);
				}
			}
		}
		return isValid;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean isValidToken(AuthToken token) {
		return super.isValidToken(token);
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean invalidateToken(AuthToken token) {
		boolean result = false;
		if (token != null) {
			result = invalidateToken(token.getTokenId());
		}
		return result;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean invalidateToken(String tokenId) {
		boolean result = super.invalidateToken(tokenId);

		if (tokenMap.containsKey(tokenId)) {
			tokenMap.remove(tokenId);
		}

		return result;
	}

}
