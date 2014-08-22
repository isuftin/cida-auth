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
	public void testCreateDefault() throws InterruptedException {
		System.out.println("create");
		String username = "test";
		long now = new Date().getTime();
		Thread.sleep(1000);
		AuthToken result = AuthTokenFactory.create(username);
		assertNotNull(result);
		System.out.println(now);
		System.out.println(result.getIssued().getTime());
		assertTrue(now < result.getIssued().getTime());
		assertTrue(result.getExpires().getTime() > result.getIssued().getTime());
	}
	
}
