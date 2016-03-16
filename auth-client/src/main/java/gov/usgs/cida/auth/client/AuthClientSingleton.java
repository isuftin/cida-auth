package gov.usgs.cida.auth.client;

import java.net.URISyntaxException;

import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.usgs.cida.config.DynamicReadOnlyProperties;

public class AuthClientSingleton {
	private static final Logger LOG = LoggerFactory.getLogger(AuthClientSingleton.class);
	public static final String AUTH_SERVICE_JNDI_NAME = "cida.auth.service.endpoint";
	
	private static IAuthClient authClient;
	
	private static DynamicReadOnlyProperties props = null;
	
	private static DynamicReadOnlyProperties getPropInstance() {
		if (null == props) {
			try {
				props = new DynamicReadOnlyProperties().addJNDIContexts();
			} catch (NamingException e) {
				LOG.warn("Error occured during initing property reader", e);
			}
		}
		return props;
	}
	
	public static String getProperty(String prop) {
		return getPropInstance().getProperty(prop);
	}

	public static void initAuthClient(Class<? extends IAuthClient> authClientType) {
		String authUrl;
		
		if(authClient != null) {
			throw new IllegalStateException("cannot initialize the AuthClientSingleton more than once");
		}
		
		authUrl =  getProperty(AUTH_SERVICE_JNDI_NAME);
		
		try {
			LOG.info("Authentication/Authorization service: " + authUrl);
			if(authClientType.equals(AuthClient.class)) {
				authClient = new AuthClient(authUrl);
			} else if(authClientType.equals(CachingAuthClient.class)) {
				authClient = new CachingAuthClient(authUrl);
			} else if(authClientType.equals(NullAuthClient.class)) {
				authClient = new NullAuthClient();
			} else if(authClientType.equals(ManagedAuthClient.class)) {
				authClient = new ManagedAuthClient(authUrl);
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
