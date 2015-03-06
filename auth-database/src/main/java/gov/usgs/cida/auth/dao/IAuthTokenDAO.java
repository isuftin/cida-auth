package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;

import java.util.List;

public interface IAuthTokenDAO {

	/**
	 * Gets all available authentication tokens
	 *
	 * @return
	 */
	public List<AuthToken> getAll();

	/**
	 * Gets an authentication token based on an ID
	 *
	 * @param id
	 * @return
	 */
	public AuthToken getByTokenById(String id);

	/**
	 * Retrieves a list of role names associated with a username.
	 *
	 * @param username
	 * @return
	 */
	public List<String> getRoles(String username);

	/**
	 * Gets all tokens that have passed their expiration date
	 *
	 * @return
	 */
	public List<AuthToken> getExpiredTokens();

	/**
	 * Deletes a token based on a token ID
	 *
	 * @param id
	 * @return 1 if deleted, 0 if not
	 */
	public int deleteTokenUsingId(String id);

	/**
	 * 
	 * @return 
	 */
	public int deleteExpiredTokens();

	/**
	 * Inserts an AuthToken
	 *
	 * @param token
	 * @return 1 if inserted, 0 if not
	 */
	public int insertToken(AuthToken token);

	public int updateToken(AuthToken token);

	/**
	 * Updates AuthToken expiration based on the expiration field in the token
	 *
	 * @param token
	 * @return 1 if updated, 0 if not
	 */
	public int updateTokenExpiration(AuthToken token);

	/**
	 * Updates the AuthToken last access based on the last access field in the
	 * token
	 *
	 * @param token
	 * @return
	 */
	public int updateTokenLastAccess(AuthToken token);

	/**
	 * Create and insert an AuthToken with the set of roles. Will expired in 1 day.
	 * 
	 * @param roles
	 * @return AuthToken
	 */
	public AuthToken create(User user);

	/**
	 * Create and insert an AuthToken with the set of roles and duration.
	 * 
	 * @param roles
	 * @param ttl seconds until this AuthToken expires
	 * @return AuthToken
	 */
	public AuthToken create(User user, int ttl);

	/**
	 * Do a cheap check if a token exists
	 *
	 * @param tokenId
	 * @return
	 */
	public boolean exists(String tokenId);

}