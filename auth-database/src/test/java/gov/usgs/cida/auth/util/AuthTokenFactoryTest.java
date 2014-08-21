package gov.usgs.cida.auth.util;

import gov.usgs.cida.auth.model.AuthToken;
import java.util.Date;
import static org.junit.Assert.*;
import org.junit.Test;

/**
 *
 * @author isuftin
 */
public class AuthTokenFactoryTest {
	
	public AuthTokenFactoryTest() {
	}

	@Test
	public void testCreateDefault() {
		System.out.println("create");
		String username = "test";
		long now = new Date().getTime();
		AuthToken result = AuthTokenFactory.create(username);
		assertNotNull(result);
		assertTrue(now < result.getIssued().getTime());
		assertTrue(result.getExpires().getTime() > result.getIssued().getTime());
	}
	
}
