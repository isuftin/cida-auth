package gov.usgs.cida.auth.client;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import gov.usgs.cida.auth.model.AuthToken;

import java.net.URISyntaxException;

import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author isuftin
 * @author thongsav
 */
public class CachingAuthClientTest extends AuthClientTest {
	public CachingAuthClientTest() {
	}
	
	@Before
	public void setUpCaching() throws URISyntaxException {
		instance = new CachingAuthClient(authUrl);
	}

	@Test
	@Override
	public void testGetNewToken() throws URISyntaxException {
		super.testGetNewToken();
		mockServer.reset(); //these stops the server from responding to requests
		
		String username = "testuser";
		String password = "testpassword";
		AuthToken result = instance.getNewToken(username, password);
		assertNull(result); //asking for a new token requires a responding server
	}
	
	@Test
	@Override
	public void testGetRolesByToken() throws URISyntaxException {
		super.testGetRolesByToken();
		mockServer.reset(); //these stops the server from responding to requests
		super.testGetRolesByToken(); //tests should still pass
	}

	@Test
	@Override
	public void testGetNewTokenWithErrorCode() throws URISyntaxException {
		super.testGetNewTokenWithErrorCode();
		mockServer.reset(); //these stops the server from responding to requests
		super.testGetNewTokenWithErrorCode(); //tests should still pass
	}

	@Test
	@Override
	public void testInvalidateToken() throws URISyntaxException {
		super.testInvalidateToken();
		mockServer.reset(); //these stops the server from responding to requests
		
		boolean deleted = instance.invalidateToken(tokenId);
		assertThat(deleted, is(false)); //no server response confirming a delete occured
	}

	@Test
	@Override
	public void testInvalidateTokenWithInvalidTokenID() throws URISyntaxException {
		super.testInvalidateTokenWithInvalidTokenID();
		mockServer.reset(); //these stops the server from responding to requests
		super.testInvalidateTokenWithInvalidTokenID(); //tests should still pass
	}

	@Test
	@Override
	public void testGetToken() throws URISyntaxException {
		super.testGetToken();
		mockServer.reset(); //these stops the server from responding to requests
		
		//non-expired tokens are taken from cache
		System.out.println("getToken");
		AuthToken result = instance.getToken(tokenId);
		assertNotNull(result);
		assertThat(result.getTokenId(), is(equalTo("fda34827-f5d7-44d7-b46f-db6603accb7c")));
		assertThat(result.getExpires(), is(notNullValue()));
		assertThat(result.getIssued(), is(notNullValue()));
		assertThat(result.getLastAccess(), is(notNullValue()));
		assertFalse(result.isExpired());
		
		//expired tokens are discarded from cache
		AuthToken result2 = instance.getToken(expiredTokenId);
		assertNull(result2);
	}

	@Test
	@Override
	public void testGetWrongToken() throws URISyntaxException {
		super.testGetWrongToken();
		mockServer.reset(); //these stops the server from responding to requests
		super.testGetWrongToken(); //tests should still pass
	}

}
