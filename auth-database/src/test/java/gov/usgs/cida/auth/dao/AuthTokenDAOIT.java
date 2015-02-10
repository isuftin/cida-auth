package gov.usgs.cida.auth.dao;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
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
	private User user;
	private List<String> roles;

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
		roles = new ArrayList<String>();
		roles.add("read-only");
		user = new User();
		user.setUsername("test-user");
		user.setRoles(roles);
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
		AuthToken result = dao.getByTokenById("88AD43FE-58FA-12E8-41C1-72F0E20D9F1F");
		assertThat(result, is(notNullValue()));
	}

	@Test
	public void testUpdateExpiration() {
		System.out.println("testUpdateExpiration");
		AuthToken token = dao.getByTokenById("88AD43FE-58FA-12E8-41C1-72F0E20D9F1F");
		assertThat(token, is(notNullValue()));

		long originalExpiration = token.getExpires().getTime();
		int seconds = 600;
		long updatedSeconds = seconds * 1000l;
		token.extendExpiration(seconds);
		dao.updateTokenExpiration(token);

		AuthToken result = dao.getByTokenById("88AD43FE-58FA-12E8-41C1-72F0E20D9F1F");
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

		AuthToken token = dao.create(user);
		String tokenId = "TEST-TOKEN-ID";

		token.setTokenId(tokenId);
		token.setIssued(new Timestamp(now));
		token.setExpires(new Timestamp(tomorrow));
		token.setLastAccess(new Timestamp(now));

		int insertCount = dao.insertToken(token);
		assertThat(insertCount, is(equalTo(1)));

		AuthToken result = dao.getByTokenById(tokenId);
		assertThat(result, is(notNullValue()));
		assertThat(result.getTokenId(), is(equalTo(tokenId)));
		assertThat(result.getIssued().getTime(), is(equalTo(now)));
		assertThat(result.getExpires().getTime(), is(equalTo(tomorrow)));
		assertThat(result.getLastAccess().getTime(), is(equalTo(now)));
	}

	@Test
	public void testExists() {
		System.out.println("testExists");
		
		AuthToken token = dao.create(user, 600);
		dao.insertToken(token);
		
		assertThat(dao.exists(token.getTokenId()), is(true));
	}

	@Test
	public void testGetExpiredTokens() {
		System.out.println("testGetExpiredTokens");

		// I want to update the expiration date on all tokens in the database
		List<AuthToken> results = dao.getExpiredTokens();
		for (AuthToken result : results) {
			result.updateLastAccess();
			result.extendExpiration();
			dao.updateToken(result);
		}

		Calendar cal = Calendar.getInstance();
		Date dt = new Date();
		long now = dt.getTime();

		cal.setTime(dt);
		cal.add(Calendar.DATE, -1);
		long yesterday = cal.getTimeInMillis();

		AuthToken token = dao.create(user);
		String tokenId = "TEST-TOKEN-ID2";

		token.setTokenId(tokenId);
		token.setIssued(new Timestamp(now));
		token.setExpires(new Timestamp(yesterday));
		token.setLastAccess(new Timestamp(now));
		dao.insertToken(token);

		results = dao.getExpiredTokens();
		assertThat(results.size(), is(equalTo(1)));
	}

}
