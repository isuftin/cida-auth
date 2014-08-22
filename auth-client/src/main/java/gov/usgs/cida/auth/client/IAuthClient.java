package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;

/**
 * Provides methods which abstract the function of a cida-auth-webservice endpoint.
 * 
 * @author thongsav
 */
public interface IAuthClient {
	
	/**
	 * Authenticates the username and password against a token service. Returns 
	 * @param username
	 * @param password
	 * @return AuthToken
	 */
	public AuthToken getNewToken(String username, String password);

	/**
	 * Checks to see if a token is currently valid.
	 * 
	 * @param token
	 * @return AuthToken
	 */
	public boolean isValidToken(String token);
	
	/**
	 * Checks to see if a token is currently valid.
	 * 
	 * @param token
	 * @return AuthToken
	 */
	public boolean isValidToken(AuthToken token);
	
	/**
	 * Invalidates the token on the auth server.
	 * 
	 * @param token
	 * @return AuthToken
	 */
	public boolean invalidateToken(AuthToken token);
	
	/**
	 * Invalidates the token on the auth server.
	 * 
	 * @param token
	 * @return AuthToken
	 */
	public boolean invalidateToken(String token);

}
