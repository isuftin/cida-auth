package gov.usgs.cida.auth.util;

import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.usgs.cida.config.DynamicReadOnlyProperties;

public class ConfigurationLoader {
	private static final Logger LOG = LoggerFactory.getLogger(ConfigurationLoader.class);
	public static final String AUTH_TTL_JNDI_NAME = "cida.auth.service.ttl.seconds";
	
	private static final Integer DEFAULT_TTL_SECONDS = 3600; //default ttl in seconds
	
	private static DynamicReadOnlyProperties props = null;
	
	private static Integer ttlSeconds = null; //default ttl in MS

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
		return getPropInstance().getJNDIPropertyUsingContexts(prop);
	}

	public static int getTtlSeconds() {
		if(ttlSeconds == null) {
			try {
				ttlSeconds = Integer.parseInt(getProperty(AUTH_TTL_JNDI_NAME));
			} catch (NumberFormatException e) {
				LOG.warn("Could not read cida.auth.service.ttl.seconds, using default of " + DEFAULT_TTL_SECONDS);
				ttlSeconds = DEFAULT_TTL_SECONDS;
			}
		}
		return ttlSeconds;
	}
}
