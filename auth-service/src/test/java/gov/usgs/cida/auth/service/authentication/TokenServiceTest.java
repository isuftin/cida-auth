package gov.usgs.cida.auth.service.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import gov.usgs.cida.auth.exception.NotAuthorizedException;
import gov.usgs.cida.auth.model.AuthToken;

import org.junit.Test;

public class TokenServiceTest {

	@Test
	public void testCidaActiveDirectoryTokenServiceAuthenticate() {
		CidaActiveDirectoryTokenService authService = new CidaActiveDirectoryTokenService(new TestTokenDAO(), new TestAuthService());
		
		AuthToken token = null;
		try {
			token = authService.authenticate("validUser", "validPassword".toCharArray());
		} catch (NotAuthorizedException e) {
		}
		assertNotNull(token);
		assertEquals(token.getUsername(), "validUser");
		
		try {
			token = authService.authenticate("notAUser", "badPassword".toCharArray());
			assertTrue("Unauthaurized users should throw a NotAuthorizedException", false);
		} catch (NotAuthorizedException e) {
			assertTrue("Unauthaurized users should throw a NotAuthorizedException", true);
		}
	}
	
	@Test
	public void testManagedAuthTokenServiceAuthenticate() {
		ManagedAuthTokenService authService = new ManagedAuthTokenService(new TestTokenDAO(), new TestAuthService());
		
		AuthToken token = null;
		try {
			token = authService.authenticate("validUser", "validPassword".toCharArray());
		} catch (NotAuthorizedException e) {
		}
		assertNotNull(token);
		assertEquals(token.getUsername(), "validUser");
		
		try {
			token = authService.authenticate("notAUser", "badPassword".toCharArray());
			assertTrue("Unauthaurized users should throw a NotAuthorizedException", false);
		} catch (NotAuthorizedException e) {
			assertTrue("Unauthaurized users should throw a NotAuthorizedException", true);
		}
	}
}
