package gov.usgs.cida.auth.dao;

import gov.usgs.cida.auth.model.AuthToken;
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
	public void testExtendExpiration() {
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
}
