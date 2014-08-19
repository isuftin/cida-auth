package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.util.MyBatisConnectionFactory;
import java.math.BigInteger;
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
	 * @return 
	 */
	public List<AuthToken> getAll() {
		List<AuthToken> result;
		
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.selectList("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.getAll");
		}
		
		return result;
	}
	
	public AuthToken getByTokenId(String id) {
		AuthToken result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.selectOne("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.getByTokenId", id);
		}
		return result;
	}
	
	public int deleteTokenUsingId(String id) {
		int result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.delete("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.deleteTokenUsingId", id);
			session.commit();
		}
		return result;
	}
	
	public int insertToken(AuthToken token) {
		int result;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.insert("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.insertToken", token);
			session.commit();
		}
		return result;
	}
	
}
