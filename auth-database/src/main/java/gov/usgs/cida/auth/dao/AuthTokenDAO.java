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
	
	public List<AuthToken> getAll() {
		List<AuthToken> result;
		
		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.selectList("gov.usgs.cida.mybatis.mappers.AuthTokenMapper.getAll");
		}
		
		return result;
	}
	
}
