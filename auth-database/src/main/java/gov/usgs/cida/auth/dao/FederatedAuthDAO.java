package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.util.MyBatisConnectionFactory;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;

/**
 * DAO layer used to retrieve configration about accepted OID/SAML configuration
 *
 * @author thongsav
 */
public class FederatedAuthDAO implements IFederatedAuthDAO {

	private final SqlSessionFactory sqlSessionFactory;
	final static String FED_AUTH_MAPPER_PACKAGE = "gov.usgs.cida.mybatis.mappers.FederatedAuthMapper";

	public FederatedAuthDAO() {
		sqlSessionFactory = MyBatisConnectionFactory.getSqlSessionFactory();
	}

	public FederatedAuthDAO(SqlSessionFactory factory) {
		sqlSessionFactory = factory;
	}
	
	/* (non-Javadoc)
	 * @see gov.usgs.cida.auth.dao.IFederatedAuthDAO#getAllAcceptedDomains()
	 */
	@Override
	public List<String> getAllAcceptedDomains() {
		List<String> results;
		try (SqlSession session = sqlSessionFactory.openSession()) {
			results = session.selectList(FED_AUTH_MAPPER_PACKAGE + ".getAllAcceptedDomains");
		}
		return results;
	}

	/* (non-Javadoc)
	 * @see gov.usgs.cida.auth.dao.IFederatedAuthDAO#getAllAcceptedForwardUrls()
	 */
	@Override
	public List<String> getAllAcceptedForwardUrls() {
		List<String> result;

		try (SqlSession session = sqlSessionFactory.openSession()) {
			result = session.selectList(FED_AUTH_MAPPER_PACKAGE + ".getAllAcceptedForwardUrls");
		}

		return result;
	}
}
