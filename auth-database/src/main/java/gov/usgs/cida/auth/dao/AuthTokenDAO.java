package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
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
			result = session.selectList("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.getAll");
		}

		return result;
	}

	/**
	 * Gets an authentication token based on an ID
	 *
	 * @param id
	 * @return
	 */
	public AuthToken getByTokenId(String id) {
		AuthToken result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.selectOne("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.getByTokenId", id);
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
			result = session.delete("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.deleteTokenUsingId", id);
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
			result = session.insert("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.insertToken", token);
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
			result = session.update("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.updateTokenExpiration", token);
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
			result = session.update("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.updateTokenLastAccess", token);
			session.commit();
		}
		return result;
	}

}
