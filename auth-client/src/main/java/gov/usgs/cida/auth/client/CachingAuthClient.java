package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * @author isuftin
 */
public class CachingAuthClient extends AuthClient {

	private static Map<String, AuthToken> tokenMap = new ConcurrentHashMap<>();
	
	public CachingAuthClient(String authEndpoint) throws URISyntaxException {
		super(authEndpoint);
	}
	
	/**
	 * 
	 * @param username
	 * @param password
	 * @return 
	 */
	@Override
	public AuthToken getNewToken(String username, String password) {
		AuthToken token = super.getNewToken(username, password);
		if (token != null) {
			tokenMap.put(token.getTokenId(), token);
		}
		return token;
	}
	
}
