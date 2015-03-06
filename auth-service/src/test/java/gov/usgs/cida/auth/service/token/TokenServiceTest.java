package gov.usgs.cida.auth.service.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.junit.Test;

import gov.usgs.cida.auth.exception.ExpiredTokenException;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.service.TestTokenDAO;

public class TokenServiceTest {
	@Test
	public void testValidateToken() {
		TokenService testService = new TokenService(new TestTokenDAO());
		
		testService.validateToken("validTokenId"); //no exception
		
		try {
			testService.validateToken("expiredTokenId");
			assertTrue("An ExpiredTokenException should have been thrown here", false);
		} catch (ExpiredTokenException e) {
			assertTrue("An ExpiredTokenException should have been thrown here", true);
		}
	}
	
	@Test
	public void testTokenExists () {
		TokenService testService = new TokenService(new TestTokenDAO());
		
		assertTrue("Token exists", testService.tokenExists("validTokenId"));
		assertTrue("Token exists", testService.tokenExists("expiredTokenId"));
		assertFalse("Token does not exist", testService.tokenExists("blah"));
	}
	
	@Test
	public void testDeleteToken() {
		TokenService testService = new TokenService(new TestTokenDAO());
		
		//not the greatest test, essentially passing through to a fake DAO, not sure how "real" this is
		assertEquals(testService.deleteToken("expiredTokenId"), 0);
		assertEquals(testService.deleteToken("deletableToken"), 1);
	}
	
	@Test
	public void testGetRolesByTokenId() {
		TokenService testService = new TokenService(new TestTokenDAO());
		
		try {
			testService.getRolesByTokenId("expiredTokenId"); //not allowed to retrieve roles for expired tokens
			assertTrue("An ExpiredTokenException should have been thrown here", false);
		} catch (ExpiredTokenException e) {
			assertTrue("An ExpiredTokenException should have been thrown here", true);
		}
		
		List<String> roles = testService.getRolesByTokenId("validTokenId");
		assertEquals(roles.size(), 1);
		assertEquals(roles.get(0), "ROLE2");
	}
	
	@Test
	public void testGetTokenById() throws InterruptedException {
		TokenService testService = new TokenService(new TestTokenDAO());
		
		try {
			testService.getTokenById("expiredTokenId"); //not allowed to retrieve expired tokens
			assertTrue("An ExpiredTokenException should have been thrown here", false);
		} catch (ExpiredTokenException e) {
			assertTrue("An ExpiredTokenException should have been thrown here", true);
		}
		
		//Construct a bunch of time ranges, so we can compare times, since code is moving we can't match exact times
		Calendar cal = Calendar.getInstance();
		Date nowDate = new Date();
		cal.setTime(nowDate);
				
		long now = nowDate.getTime();
		cal.add(Calendar.SECOND, 1);
		long oneSecFromNow = cal.getTimeInMillis();

		cal.add(Calendar.SECOND, 4);
		long fiveSecFromNow = cal.getTimeInMillis();

		cal.add(Calendar.HOUR, 1);
		long oneHourFiveSecFromNow = cal.getTimeInMillis();
		
		cal.add(Calendar.SECOND, -5);
		long oneHourFromNow = cal.getTimeInMillis();
		
		//wait a little over 1 sec to make sure enough time passes so we can test updated timestamps
		Thread.sleep(1200);
		
		AuthToken retrievedToken = testService.getTokenById("validTokenId");
		Timestamp expires = retrievedToken.getExpires();
		Timestamp lastRetrieved = retrievedToken.getLastAccess();
		
		//Verify that the lastAccess time was updated
		assertTrue("Last access time was updated to just now", lastRetrieved.after(new Timestamp(oneSecFromNow)));
		assertTrue("Last access time was updated to just now", lastRetrieved.before(new Timestamp(fiveSecFromNow)));
		
		//Verify that expiration time was reset to an hour after the last access time
		assertTrue("Expire time was set to an hour after last access time", expires.after(new Timestamp(oneHourFromNow)));
		assertTrue("Expire time was set to an hour after last access time", expires.before(new Timestamp(oneHourFiveSecFromNow)));
		
	}
}
