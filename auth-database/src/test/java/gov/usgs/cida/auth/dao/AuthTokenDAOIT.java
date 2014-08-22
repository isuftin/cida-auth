package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import org.junit.After;
import org.junit.AfterClass;
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
	private AuthTokenDAO dao;

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
		dao = new AuthTokenDAO(sqlSessionFactory);
	}

	@After
	public void tearDown() {
	}

	@Test
	public void testGetAll() {
		System.out.println("getAll");
		List<AuthToken> result = dao.getAll();
		assertThat(result, is(notNullValue()));
		assertThat(result.size(), greaterThan(1));
	}

	@Test
	public void testGetByTokenId() {
		System.out.println("getByTokenId");
		AuthToken result = dao.getByTokenId("88AD43FE-58FA-12E8-41C1-72F0E20D9F1F");
		assertThat(result, is(notNullValue()));
		assertThat(result.getUsername(), is(equalTo("lobortis@diam.com")));
	}
	
	@Test
	public void testUpdateExpiration() {
		System.out.println("testUpdateExpiration");
		AuthToken token = dao.getByTokenId("88AD43FE-58FA-12E8-41C1-72F0E20D9F1F");
		assertThat(token, is(notNullValue()));
		
		long originalExpiration = token.getExpires().getTime();
		int seconds = 600;
		long updatedSeconds = seconds * 1000l;
		token.extendExpiration(seconds);
		dao.updateTokenExpiration(token);
		
		AuthToken result = dao.getByTokenId("88AD43FE-58FA-12E8-41C1-72F0E20D9F1F");
		assertThat(result, is(notNullValue()));
		assertThat(result.getExpires().getTime() - originalExpiration, is(equalTo(updatedSeconds)));
	}

	@Test
	public void testDeleteTokenUsingId() {
		System.out.println("deleteTokenUsingId");
		int result = dao.deleteTokenUsingId("BCFCAA99-18D7-5833-FD50-AFE27E7AF1ED");
		assertThat(result, is(equalTo(1)));
	}

	@Test
	public void testInsertToken() {
		System.out.println("insertToken");
		Calendar cal = Calendar.getInstance();
		Date dt = new Date();
		long now = dt.getTime();

		cal.setTime(dt);
		cal.add(Calendar.DATE, 1);
		long tomorrow = cal.getTimeInMillis();

		AuthToken token = new AuthToken();
		String tokenId = "TEST-TOKEN-ID";
		String username = "isuftin@usgs.gov";

		token.setTokenId(tokenId);
		token.setUsername(username);
		token.setIssued(new Timestamp(now));
		token.setExpires(new Timestamp(tomorrow));
		token.setLastAccess(new Timestamp(now));

		int insertCount = dao.insertToken(token);
		assertThat(insertCount, is(equalTo(1)));

		AuthToken result = dao.getByTokenId(tokenId);
		assertThat(result, is(notNullValue()));
		assertThat(result.getTokenId(), is(equalTo(tokenId)));
		assertThat(result.getUsername(), is(equalTo(username)));
		assertThat(result.getIssued().getTime(), is(equalTo(now)));
		assertThat(result.getExpires().getTime(), is(equalTo(tomorrow)));
		assertThat(result.getLastAccess().getTime(), is(equalTo(now)));

	}

}
