package gov.usgs.cida.auth.util;

import gov.usgs.cida.auth.model.AuthToken;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;

/**
 * Creates an AuthToken given a username and optionally, time to live
 *
 * @author isuftin
 */
public class AuthTokenFactory {

	protected static final int ONE_DAY_IN_SECONDS = 86_400;

	private AuthTokenFactory() {
		// No instantiation
	}

	/**
	 * Create a new auth token with the provided user name. By default, will
	 * expire in 1 day
	 *
	 * @param username
	 * @return
	 */
	public static AuthToken create(String username) {
		return create(username, ONE_DAY_IN_SECONDS);
	}

	/**
	 * Create a new auth token with the provided user name.
	 *
	 * @param username
	 * @param ttl time to live for token in terms of seconds
	 * @return
	 */
	public static AuthToken create(String username, int ttl) {
		if (StringUtils.isBlank(username)) {
			throw new IllegalArgumentException("Username may not be null or blank");
		}
		AuthToken result = new AuthToken();
		Calendar cal = Calendar.getInstance();
		Date nowDate = new Date();
		cal.setTime(nowDate);
		cal.add(Calendar.SECOND, ttl);
				
		long now = nowDate.getTime();
		long expires = cal.getTimeInMillis();
		
		result.setTokenId(UUID.randomUUID().toString());
		result.setUsername(username);
		result.setIssued(new Timestamp(now));
		result.setLastAccess(null);
		result.setExpires(new Timestamp(expires));
		
		return result;
	}
}
