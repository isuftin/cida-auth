package gov.usgs.cida.auth.client;

import java.net.URISyntaxException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthClientSingleton {
	private static final Logger LOG = LoggerFactory.getLogger(AuthClientSingleton.class);
	public static final String AUTH_SERVICE_JNDI_NAME = "cida.auth.service.endpoint";
	
	private static IAuthClient authClient;

	public static void initAuthClient(Class<? extends IAuthClient> authClientType) {
		String authUrl;
		
		if(authClient != null) {
			throw new IllegalStateException("cannot initialize the AuthClientSingleton more than once");
		}
		
		try {
			Context ctx = new InitialContext();
			authUrl =  (String) ctx.lookup("java:comp/env/" + AUTH_SERVICE_JNDI_NAME);
		} catch (NamingException ex) {
			LOG.info("JNDI name cida.auth.service.endpoint must be set to the target authentication service URL");
			authUrl = "";
		}
		try {
			LOG.info("Authentication/Authorization service: " + authUrl);
			if(authClientType.equals(AuthClient.class)) {
				authClient = new AuthClient(authUrl);
			} else if(authClientType.equals(CachingAuthClient.class)) {
				authClient = new CachingAuthClient(authUrl);
			} else {
				LOG.warn("Unknown IAuthClient type");
			}
		} catch (URISyntaxException e) {
			LOG.error("Failed to initialize authorization client", e);
		}
	}
	
	public static boolean isInitialized() {
		return authClient != null;
	}
	
	public static IAuthClient getAuthClient() {
		if(authClient == null) {
			throw new IllegalStateException("IAuthClient has not been initialized.");
		}
		return authClient;
	}
}
