package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;
import gov.usgs.cida.auth.util.MyBatisConnectionFactory;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;

/**
 * DAO layer for the AuthToken
 *
 * @author isuftin
 */
public class AuthTokenDAO {

	private final SqlSessionFactory sqlSessionFactory;
	final static String TOKEN_MAPPER_PACKAGE = "gov.usgs.cida.mybatis.mappers.AuthTokenMapper";
	private static final int ONE_HOUR_IN_SECONDS = 3_600;

	public AuthTokenDAO() {
		sqlSessionFactory = MyBatisConnectionFactory.getSqlSessionFactory();
	}

	public AuthTokenDAO(SqlSessionFactory factory) {

		sqlSessionFactory = factory;
	}

	/**
	 * Gets all available authentication tokens
	 *
	 * @return
	 */
	public List<AuthToken> getAll() {
		List<AuthToken> result;

		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.selectList(TOKEN_MAPPER_PACKAGE + ".getAll");
		}

		return result;
	}

	/**
	 * Gets an authentication token based on an ID
	 *
	 * @param id
	 * @return
	 */
	public AuthToken getByTokenById(String id) {
		AuthToken result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.selectOne(TOKEN_MAPPER_PACKAGE + ".getByTokenById", id);
		}
		return result;
	}
	
	/**
	 * Retrieves a list of role names associated with a username.
	 *
	 * @param username
	 * @return
	 */
	public List<String> getRoles(String username) {
		List<String> results;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			results = session.selectList(TOKEN_MAPPER_PACKAGE + ".getSyncopeRoles", username);
		}
		return results;
	}

	/**
	 * Gets all tokens that have passed their expiration date
	 *
	 * @return
	 */
	public List<AuthToken> getExpiredTokens() {
		List<AuthToken> result;

		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.selectList(TOKEN_MAPPER_PACKAGE + ".getExpiredTokens");
		}

		return result;
	}

	/**
	 * Deletes a token based on a token ID
	 *
	 * @param id
	 * @return 1 if deleted, 0 if not
	 */
	public int deleteTokenUsingId(String id) {
		int result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.delete(TOKEN_MAPPER_PACKAGE + ".deleteTokenUsingId", id);
			session.commit();
		}
		return result;
	}
	
	/**
	 * 
	 * @return 
	 */
	public int deleteExpiredTokens() {
		int result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.delete(TOKEN_MAPPER_PACKAGE + ".deleteExpiredTokens");
			session.commit();
		}
		return result;
	}
 
	/**
	 * Inserts an AuthToken
	 *
	 * @param token
	 * @return 1 if inserted, 0 if not
	 */
	public int insertToken(AuthToken token) {
		int result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.insert(TOKEN_MAPPER_PACKAGE + ".insertToken", token);
			session.commit();
		}
		AuthToken savedToken = getByTokenById(token.getTokenId());
		if (null != savedToken) {
			BigInteger savedTokenId = savedToken.getId();
			try (SqlSession session = sqlSessionFactory.openSession()) {
				for (String role : token.getRoles()) {
					Map<String, Object> map = new HashMap<>();
					map.put("id", savedTokenId);
					map.put("roleName", role);
					result = session.insert(TOKEN_MAPPER_PACKAGE + ".insertRole", map);
				}
				session.commit();
			}
		}
		return result;
	}

	public int updateToken(AuthToken token) {
		int result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.update(TOKEN_MAPPER_PACKAGE + ".updateToken", token);
			session.commit();
		}
		return result;
	}

	/**
	 * Updates AuthToken expiration based on the expiration field in the token
	 *
	 * @param token
	 * @return 1 if updated, 0 if not
	 */
	public int updateTokenExpiration(AuthToken token) {
		int result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.update(TOKEN_MAPPER_PACKAGE + ".updateTokenExpiration", token);
			session.commit();
		}
		return result;
	}

	/**
	 * Updates the AuthToken last access based on the last access field in the
	 * token
	 *
	 * @param token
	 * @return
	 */
	public int updateTokenLastAccess(AuthToken token) {
		int result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.update(TOKEN_MAPPER_PACKAGE + ".updateTokenLastAccess", token);
			session.commit();
		}
		return result;
	}
	
	/**
	 * Create and insert an AuthToken with the set of roles. Will expired in 1 day.
	 * 
	 * @param roles
	 * @return AuthToken
	 */
	public AuthToken create(User user) {
		return create(user, ONE_HOUR_IN_SECONDS);
	}
	
	/**
	 * Create and insert an AuthToken with the set of roles and duration.
	 * 
	 * @param roles
	 * @param ttl seconds until this AuthToken expires
	 * @return AuthToken
	 */
	public AuthToken create(User user, int ttl) {
		String username = user.getUsername();
		if (StringUtils.isBlank(username)) {
			throw new IllegalArgumentException("Username may not be null or empty");
		}

		List<String> roles = user.getRoles();

		AuthToken token = new AuthToken();

		Calendar cal = Calendar.getInstance();
		Date nowDate = new Date();
		cal.setTime(nowDate);
		cal.add(Calendar.SECOND, ttl);
				
		long now = nowDate.getTime();
		long expires = cal.getTimeInMillis();
		Timestamp nowTs = new Timestamp(now);
		Timestamp expiresTs = new Timestamp(expires);
		
		token.setTokenId(UUID.randomUUID().toString());
		token.setUsername(username);
		token.setIssued(nowTs);
		token.setLastAccess(nowTs);
		token.setExpires(expiresTs);
		token.setRoles(roles);
		
		insertToken(token);
		
		return token;
	}

	/**
	 * Do a cheap check if a token exists
	 *
	 * @param tokenId
	 * @return
	 */
	public boolean exists(String tokenId) {
		boolean exists = false;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			Integer count = session.selectOne(TOKEN_MAPPER_PACKAGE + ".getCountForId", tokenId);
			if (count != null && count > 0) {
				exists = true;
			}
		}
		return exists;
	}

}
