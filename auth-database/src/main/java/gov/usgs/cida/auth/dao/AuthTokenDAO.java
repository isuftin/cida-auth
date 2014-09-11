package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.util.AuthTokenFactory;
import gov.usgs.cida.auth.util.MyBatisConnectionFactory;
import java.util.List;
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
	 * Retrieves a list of role names associated with a token.
	 *
	 * @param tokenId
	 * @return token created and inserted into database
	 */
	public List<String> getRolesByToken(String tokenId) {
		List<String> results;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			results = session.selectList(TOKEN_MAPPER_PACKAGE + ".getRolesByToken", tokenId);
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
	 * Creates a default token given a username and inserts it into the database
	 *
	 * @param username
	 * @return token created and inserted into database
	 */
	public AuthToken create(String username) {
		AuthToken token = AuthTokenFactory.create(username);
		insertToken(token);
		return getByTokenById(token.getTokenId());
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
			int count = session.selectOne(TOKEN_MAPPER_PACKAGE + ".getCountForId", tokenId);
			if (count > 0) {
				exists = true;
			}
		}
		return exists;
	}

}
