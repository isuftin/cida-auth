package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import static org.hamcrest.CoreMatchers.*;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 *
 * @author isuftin
 */
@Category(IntegrationTests.class)
public class AuthTokenDAOIT {

	private static SqlSessionFactory sqlSessionFactory;

	public AuthTokenDAOIT() {
	}

	@BeforeClass
	public static void setUpClass() {
		try (InputStream inputStream = Resources.getResourceAsStream("mybatis-config.xml")) {
			sqlSessionFactory = new SqlSessionFactoryBuilder().build(inputStream, "integration-test");
		} catch (IOException ex) {
			System.out.println("Error initializing SqlSessionFactoryBuilder: " + ex);
		}
	}

	@AfterClass
	public static void tearDownClass() {
	}

	@Before
	public void setUp() {
	}

	@After
	public void tearDown() {
	}

	@Test
	public void testGetAll() {
		System.out.println("getAll");
		AuthTokenDAO dao = new AuthTokenDAO(sqlSessionFactory);
		List<AuthToken> result = dao.getAll();
		assertThat(result, is(notNullValue()));
		assertThat(result.size(), is(equalTo(100)));
	}

}
