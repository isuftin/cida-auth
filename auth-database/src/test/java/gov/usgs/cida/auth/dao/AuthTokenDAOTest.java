package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.util.AuthTokenFactory;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import org.junit.Test;

/**
 *
 * @author isuftin
 */
public class AuthTokenDAOTest {

	@Test
	public void testExtendExpirationUsingSeconds() {
		System.out.println("testExtendExpirationUsingSeconds");
		AuthToken token = new AuthToken();
		String tokenId = "TEST-TOKEN-ID";
		String username = "isuftin@usgs.gov";
		Calendar cal = Calendar.getInstance();
		Date dt = new Date();
		long now = dt.getTime();

		cal.setTime(dt);
		cal.add(Calendar.DATE, 1);
		long tomorrow = cal.getTimeInMillis();

		token.setTokenId(tokenId);
		token.setUsername(username);
		token.setIssued(new Timestamp(now));
		token.setExpires(new Timestamp(tomorrow));
		token.setLastAccess(new Timestamp(now));

		int seconds = 60;
		long sixtyMillis = seconds * 1000l;
		token.extendExpiration(seconds);

		Timestamp expires = token.getExpires();
		assertThat(expires.getTime(), is(greaterThan(tomorrow)));
		assertThat((expires.getTime() - tomorrow), is(equalTo(sixtyMillis)));
	}
	
	@Test
	public void testExtendExpiration() {
		System.out.println("testExtendExpiration");
		AuthToken token = new AuthToken();
		String tokenId = "TEST-TOKEN-ID";
		String username = "isuftin@usgs.gov";
		Calendar cal = Calendar.getInstance();
		Date dt = new Date();
		long now = dt.getTime();

		cal.setTime(dt);
		cal.add(Calendar.DATE, 1);
		long tomorrow = cal.getTimeInMillis();

		token.setTokenId(tokenId);
		token.setUsername(username);
		token.setIssued(new Timestamp(now));
		token.setExpires(new Timestamp(now));
		token.setLastAccess(new Timestamp(now));

		// Extend it one day
		token.extendExpiration();
		Timestamp expires = token.getExpires();
		assertThat(expires.getTime(), is(equalTo(tomorrow)));
		
		// Extend it another day
		token.setLastAccess(new Timestamp(tomorrow));
		token.extendExpiration();
		expires = token.getExpires();
		assertThat(expires.getTime(), is(greaterThan(tomorrow)));
	}
	
	@Test
	public void testIsExpired() {
		System.out.println("testIsExpired");
		AuthToken token = AuthTokenFactory.create("test");
		Date dt = new Date();
		Calendar cal = Calendar.getInstance();
		cal.setTime(dt);
		cal.add(Calendar.DATE, -1);
		long yesterday = cal.getTimeInMillis();
		token.setExpires(new Timestamp(yesterday));
		
		boolean expired = token.isExpired();
		assertThat(expired, is(Boolean.TRUE));
	}
}
