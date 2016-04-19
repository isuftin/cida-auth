package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;

import java.net.URISyntaxException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.login.LoginException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An auth client with an internal map of tokens. Using this class will attempt
 * to cut down on traffic between the client and server when possible
 *
 * @author isuftin
 */
public class CachingAuthClient extends AuthClient {

	private static final Logger LOG = LoggerFactory.getLogger(CachingAuthClient.class);
	private static final Map<String, AuthToken> tokenCache = new ConcurrentHashMap<>();
	private static final Map<String, List<String>> rolesCache = new ConcurrentHashMap<>();

	public CachingAuthClient(String authEndpoint) throws URISyntaxException {
		super(authEndpoint);
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public AuthToken getNewToken(String username, String password) throws LoginException {
		AuthToken token = super.getNewToken(username, password);
		if (token != null) {
			tokenCache.put(token.getTokenId(), token);
			LOG.trace("Added token {} to cache", token.getTokenId());
		}
		return token;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public AuthToken getToken(String tokenId) {
		AuthToken token;
		
		// First, check the cache to see if it has a token 
		if (tokenCache.containsKey(tokenId)) {
			LOG.trace("Token {} found in cache.", tokenId);
			token = tokenCache.get(tokenId);
			if (!isValidToken(token)) {
				token = super.getToken(tokenId);
				LOG.trace("Token {} in cache was invalid. Double checking server.", tokenId);
				if (!isValidToken(token)) {
					LOG.trace("Token {} is invalid on server. Removing token from cache.", tokenId);
					invalidateToken(token);
					token = null;
				} else {
					LOG.trace("Updated token {} found on token server. Updating cache.", tokenId);
					tokenCache.put(token.getTokenId(), token);
				}
			}
		} else {
			LOG.trace("Token {} not found in cache. Will try to pull from server.", tokenId);
			token = super.getToken(tokenId);
			if (token != null) {
				LOG.trace("Token {} found found on server. Adding to cache.", tokenId);
				tokenCache.put(token.getTokenId(), token);
			} else {
				LOG.trace("Token {} not found on server.", tokenId);
			}
		}

		return token;
	}
	
	@Override
	/**
	 * {@inheritDoc}
	 */
	public List<String> getRolesByToken(String tokenId) {
		List<String> roles = rolesCache.get(tokenId);
		
		if(isValidToken(tokenId)) {
		
			if (roles == null) {
				LOG.trace("Token {} not found in roles cache. Will try to pull from server.", tokenId);
				roles = super.getRolesByToken(tokenId);
				if(roles != null) {
					rolesCache.put(tokenId, roles);
				}
			}
		} else if(roles != null){ //this is the case of roles found in cache for invalid token
			roles = null;
			rolesCache.remove(tokenId);
		}
		
		return roles;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean isValidToken(String tokenId) {
		boolean isValid = false;
		if (StringUtils.isNotBlank(tokenId)) {
			LOG.trace("Checking token id {} to see if it is valid.", tokenId);
			isValid = isValidToken(getToken(tokenId));
		}
		return isValid;
	}

	@Override
	/**
	 * If a token is valid, this will set the expiration time for 15 minutes from current time.
	 * If a token is not valid, it will attempt to load the remote token and check that.
	 */
	public boolean isValidToken(AuthToken token) {
		boolean isValid = super.isValidToken(token);
		
		//extend expiry if valid
		if(isValid) {
			Calendar cal = Calendar.getInstance();
			Date nowDate = new Date();
			cal.setTime(nowDate);
			cal.add(Calendar.SECOND, 30); //15 minute extension on cached client
			
			token.setExpires(new Timestamp(cal.getTimeInMillis()));
		} else { //check server if the actual token is expered
			token = super.getToken(token.getTokenId());
			isValid = !token.isExpired();
			//update cache entry
			tokenCache.put(token.getTokenId(), token);
		}
		return isValid;
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

		if (tokenCache.containsKey(tokenId)) {
			tokenCache.remove(tokenId);
		}

		return result;
	}

}
