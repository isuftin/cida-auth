package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.service.ServicePaths;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import org.apache.commons.io.IOUtils;
import static org.hamcrest.CoreMatchers.*;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import org.mockserver.model.Header;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import org.mockserver.socket.PortFactory;

/**
 *
 * @author isuftin
 */
public class AuthClientTest {

	private static ClientAndServer mockServer;
	private static int serverPort;
	private static String authUrl;
	private static String getAuthTokenValidResponse;
	private static final String appName = "/cida-auth-app/";
	private static final String host = "http://localhost:";
	private static final String tokenId = "fda34827-f5d7-44d7-b46f-db6603accb7c";
	private AuthClient instance = null;
	public AuthClientTest() {
	}

	@BeforeClass
	public static void setUpClass() throws URISyntaxException, IOException {

		serverPort = PortFactory.findFreePort();
		mockServer = startClientAndServer(serverPort);
		authUrl = host + serverPort + appName;

		URL getAuthTokenValidResponseUrl = AuthClientTest.class.getResource("/examples/GetAuthTokenValidResponse.json");
		getAuthTokenValidResponse = IOUtils.toString(new FileInputStream(new File(getAuthTokenValidResponseUrl.toURI())));
	}

	@AfterClass
	public static void tearDownClass() {
		mockServer.stop();
	}

	@Before
	public void setUp() throws URISyntaxException {
		mockServer.reset();
		mockServer.
				when(request().withPath(appName + ServicePaths.AUTHENTICATION + "/" + ServicePaths.AD + "/" + ServicePaths.TOKEN)).
				respond(response().
						withHeaders(new Header("Content-Type", "application/json")).
						withBody(getAuthTokenValidResponse));

		mockServer.
				when(request().withPath(appName + ServicePaths.AUTHENTICATION + "/" + ServicePaths.AD + "/" + ServicePaths.TOKEN)).
				respond(response().withStatusCode(401));

		mockServer.
				when(request().withMethod("GET").withPath(appName + ServicePaths.TOKEN + "/" + tokenId)).
				respond(response().
						withHeaders(new Header("Content-Type", "application/json")).
						withBody(getAuthTokenValidResponse));

		mockServer.
				when(request().withMethod("DELETE").withPath(appName + ServicePaths.TOKEN + "/" + tokenId)).
				respond(response().withStatusCode(200));

		mockServer.
				when(request().withMethod("DELETE").withPath(appName + ServicePaths.TOKEN + "/" + tokenId + "invalid")).
				respond(response().withStatusCode(404));
		
		instance = new AuthClient(authUrl);
	}

	@After
	public void tearDown() {
		mockServer.dumpToLog();
	}

	@Test
	public void testGetNewToken() throws URISyntaxException {
		System.out.println("getNewToken");
		String username = "testuser";
		String password = "testpassword";
		AuthToken result = instance.getNewToken(username, password);
		assertNotNull(result);
		assertThat(result.getTokenId(), is(equalTo("fda34827-f5d7-44d7-b46f-db6603accb7c")));
		assertThat(result.getExpires(), is(notNullValue()));
		assertThat(result.getIssued(), is(notNullValue()));
		assertThat(result.getLastAccess(), is(notNullValue()));
	}

	@Test
	public void testGetNewTokenWithErrorCode() throws URISyntaxException {
		System.out.println("testGetNewTokenGetting401");
		String username = "testuser";
		String password = "testpassword";
		instance = new AuthClient(authUrl + "invalid");
		AuthToken result = instance.getNewToken(username, password);
		assertNull(result);
	}

	@Test
	public void testInvalidateToken() throws URISyntaxException {
		System.out.println("testInvalidateToken");
		boolean deleted = instance.invalidateToken(tokenId);
		assertThat(deleted, is(true));
	}

	@Test
	public void testInvalidateTokenWithInvalidTokenID() throws URISyntaxException {
		System.out.println("testInvalidateTokenWithInvalidTokenID");
		boolean deleted = instance.invalidateToken(tokenId + "invalid");
		assertThat(deleted, is(false));
	}

	@Test
	public void testGetToken() throws URISyntaxException {
		System.out.println("getToken");
		AuthToken result = instance.getToken(tokenId);
		assertNotNull(result);
		assertThat(result.getTokenId(), is(equalTo("fda34827-f5d7-44d7-b46f-db6603accb7c")));
		assertThat(result.getExpires(), is(notNullValue()));
		assertThat(result.getIssued(), is(notNullValue()));
		assertThat(result.getLastAccess(), is(notNullValue()));
	}

	@Test
	public void testGetWrongToken() throws URISyntaxException {
		System.out.println("testGetWrongToken");
		AuthToken result = instance.getToken(tokenId + '-');
		assertNull(result);
	}

}
