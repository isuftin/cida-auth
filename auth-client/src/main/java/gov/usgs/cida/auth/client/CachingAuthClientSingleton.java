package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.client.CachingAuthClient;
import gov.usgs.cida.auth.client.IAuthClient;

import java.net.URISyntaxException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CachingAuthClientSingleton {
	private static final Logger LOG = LoggerFactory.getLogger(CachingAuthClientSingleton.class);
	public static final String AUTH_SERVICE_JNDI_NAME = "cida.auth.service.endpoint";
	public static final String AUTHORIZATION_HEADER = "Authorization";
	
	private static IAuthClient authClient;
	static {
		String authUrl;
		try {
			Context ctx = new InitialContext();
			authUrl =  (String) ctx.lookup("java:comp/env/" + AUTH_SERVICE_JNDI_NAME);
		} catch (NamingException ex) {
			LOG.info("JNDI name cida.auth.service.endpoint must be set to the target authentication service URL");
			authUrl = "";
		}
		try {
			LOG.info("Authentication/Authorization service: " + authUrl);
			authClient = new CachingAuthClient(authUrl);
		} catch (URISyntaxException e) {
			LOG.error("Failed to initialize authorization client", e);
		}
	}
	
	public static IAuthClient getAuthClient() {
		return authClient;
	}
}
