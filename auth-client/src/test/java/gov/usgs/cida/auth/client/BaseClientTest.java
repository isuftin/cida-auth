package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.service.ServicePaths;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.mockserver.integration.ClientAndServer;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import org.mockserver.model.Header;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import org.mockserver.socket.PortFactory;

/**
 *
 * @author isuftin
 * @author thongsav
 */
public class BaseClientTest {

	protected static ClientAndServer mockServer;
	protected static int serverPort;
	protected static String authUrl;
	protected static String getAuthTokenValidResponse;
	protected static String getAuthTokenValidExpiredResponse;
	protected static String getRolesByTokenResponse;
	protected static final String appName = "/cida-auth-app/";
	protected static final String host = "http://localhost:";
	protected static final String tokenId = "fda34827-f5d7-44d7-b46f-db6603accb7c";
	protected static final String expiredTokenId = "ased4827-f5d7-44d7-b46f-db6602421asf";
	protected IAuthClient instance = null;
	public BaseClientTest() {
	}

	@BeforeClass
	public static void setUpClass() throws URISyntaxException, IOException {

		serverPort = PortFactory.findFreePort();
		mockServer = startClientAndServer(serverPort);
		authUrl = host + serverPort + appName;

		URL getAuthTokenValidResponseUrl = BaseClientTest.class.getResource("/examples/GetAuthTokenValidResponse.json");
		getAuthTokenValidResponse = IOUtils.toString(new FileInputStream(new File(getAuthTokenValidResponseUrl.toURI())));

		URL getAuthTokenValidExpiredResponseUrl = BaseClientTest.class.getResource("/examples/GetAuthTokenValidExpiredResponse.json");
		getAuthTokenValidExpiredResponse = IOUtils.toString(new FileInputStream(new File(getAuthTokenValidExpiredResponseUrl.toURI())));
		
		URL getRolesByTokenResponseUrl = BaseClientTest.class.getResource("/examples/GetRolesByTokenResponse.json");
		getRolesByTokenResponse = IOUtils.toString(new FileInputStream(new File(getRolesByTokenResponseUrl.toURI())));
	}

	@AfterClass
	public static void tearDownClass() {
		mockServer.stop();
	}

	@Before
	public void setUpBase() throws URISyntaxException {
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
			when(request().withMethod("GET").withPath(appName + ServicePaths.TOKEN + "/" + expiredTokenId)).
			respond(response().
					withHeaders(new Header("Content-Type", "application/json")).
					withBody(getAuthTokenValidExpiredResponse));
		
		mockServer.
			when(request().withMethod("GET").withPath(appName + ServicePaths.TOKEN + "/" + tokenId + "/" + ServicePaths.ROLES)).
			respond(response().
					withHeaders(new Header("Content-Type", "application/json")).
					withBody(getRolesByTokenResponse));
		
		mockServer.
				when(request().withMethod("DELETE").withPath(appName + ServicePaths.TOKEN + "/" + tokenId)).
				respond(response().withStatusCode(200));

		mockServer.
				when(request().withMethod("DELETE").withPath(appName + ServicePaths.TOKEN + "/" + tokenId + "invalid")).
				respond(response().withStatusCode(404));
	}

	@After
	public void tearDownBase() {
		mockServer.dumpToLog();
	}
}
