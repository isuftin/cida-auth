package gov.usgs.cida.auth.service.authentication;

import gov.usgs.cida.auth.model.User;
import gov.usgs.cida.config.DynamicReadOnlyProperties;

import javax.naming.NamingException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AlternativeService {

	private static final Logger LOG = LoggerFactory.getLogger(AlternativeService.class);

	private static final String JNDI_ALT_URL_PARAM_NAME = "auth.alt.url";

	private AlternativeService() {
		// Utility class, should not be instantiated
	}

	public static User authenticate(String username, char[] password) {
		User user = new User();
		user.setAuthenticated(false);
		
		DynamicReadOnlyProperties props = new DynamicReadOnlyProperties();
		try {
			props.addJNDIContexts();
		} catch (NamingException ex) {
			LOG.error("Error attempting to read JNDI properties.", ex);
		}
		
		String url = props.getProperty(JNDI_ALT_URL_PARAM_NAME);
		if (StringUtils.isBlank(url)) {
			LOG.error("Error authenticating against ALT. Check that JNDI parameters are configured.");
		} else {
			user = authenticate(username, password, url);
		}

		return user;
	}

	/**
	 * Does the heavy lifting of authenticating
	 *
	 * @param username
	 * @param password
	 * @param jndiUrl
	 * @return
	 */
	private static User authenticate(String username, char[] password, String jndiUrl) {
		User user = new User();
		
		LOG.debug("Returning a new user from ALT auth");
		LOG.debug(username);
		LOG.debug(String.valueOf(password));
		LOG.debug(jndiUrl);
		
		if (username.equalsIgnoreCase("socool") && passwordValid(password)) {
			LOG.debug("valid username: " + username);
			user.setUsername(username);
			user.setAuthenticated(true);
		}

		return user;
	}

	private static boolean passwordValid(char[] password) {
		boolean valid = String.valueOf(password).equalsIgnoreCase("floopy");
		LOG.debug("password valid: " + valid);
		return valid;
	}
}
