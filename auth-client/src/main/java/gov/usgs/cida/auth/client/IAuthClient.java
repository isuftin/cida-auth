package gov.usgs.cida.auth.client;

import java.util.List;

import gov.usgs.cida.auth.model.AuthToken;
import javax.security.auth.login.LoginException;

/**
 * Provides methods which abstract the function of a cida-auth-webservice endpoint.
 * 
 * {@link AuthClient}
 * {@link CachingAuthClient}
 * 
 * @author thongsav
 */
public interface IAuthClient {
	
	/**
	 * Authenticates the username and password against a token service.
	 * 
	 * If the user's credentials are invalid or incorrect, a LoginException is
	 * thrown.
	 * 
	 * The underlying connection implementation may throw RuntimeExceptions
	 * if the specified URL is unreachable or fails for some other reason.
	 * These are generally of type javax.ws.rs.ClientErrorException or 
	 * javax.ws.rs.ProcessingException - Catch these if you need to stop them
	 * from percolating to the UI layer.
	 * 
	 * @param username
	 * @param password
	 * @return AuthToken
	 * @throws javax.security.auth.login.LoginException If the user's credentials are invalid / incorrect
	 */
	public AuthToken getNewToken(String username, String password) throws LoginException;
	
	/**
	 * Returns a token that has the provided ID
	 * @param tokenId
	 * @return 
	 */
	public AuthToken getToken(String tokenId);
	
	/**
	 * Returns a list of role for a given token
	 * @param tokenId
	 * @return 
	 */
	public List<String> getRolesByToken(String tokenId);
	
	/**
	 * Checks to see if a token is currently valid.
	 * 
	 * @param tokenId
	 * @return AuthToken
	 */
	public boolean isValidToken(String tokenId);
	
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
	 * @param tokenId
	 * @return AuthToken
	 */
	public boolean invalidateToken(String tokenId);

}
