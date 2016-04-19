package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.service.ServicePaths;
import gov.usgs.cida.auth.util.JNDISingleton;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.MessageFormat;
import java.util.List;

import javax.ws.rs.ClientErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import javax.security.auth.login.LoginException;
import javax.ws.rs.ProcessingException;

/**
 * {@inheritDoc}
 *
 * @author thongsav
 */
public class AuthClient implements IAuthClient {
	
	private static final Logger LOG = LoggerFactory.getLogger(AuthClient.class);
	private static final boolean isDevelopment = Boolean.parseBoolean(JNDISingleton.getInstance().getProperty("development", "false"));
	final URI authEndpointUri;

	/**
	 * Initializes AuthClient with the service endpoint it will try to access
	 *
	 * @param authEndpoint the endpoint for the auth client to use
	 * @throws URISyntaxException
	 */
	public AuthClient(String authEndpoint) throws URISyntaxException {
		if (StringUtils.isBlank(authEndpoint)) {
			throw new IllegalArgumentException("Parameter authEndpoint may not be blank or null");
		}

		String _authEndpoint = authEndpoint;
		if (!_authEndpoint.endsWith("/")) {
			_authEndpoint += "/";
		}

		this.authEndpointUri = new URI(_authEndpoint);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AuthToken getNewToken(String username, String password) throws LoginException {
		Client client = createNewClient();
		AuthToken result = null;
		Form form = new Form();
		form.param("username", username);
		form.param("password", password);
		WebTarget target = client.target(this.authEndpointUri).
				path(ServicePaths.AUTHENTICATION).
				path(ServicePaths.AD).
				path(ServicePaths.TOKEN);

		try {
			Entity<Form> postEntity = Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE);
			result = target.
					request(MediaType.APPLICATION_JSON_TYPE).
					post(postEntity, AuthToken.class);
		} catch (NotAuthorizedException ex) {
			LOG.info("User {} could not authenticate. Error Code: {}, Reason: {}", username, ex.getResponse().getStatus(), ex.getResponse().getStatusInfo().getReasonPhrase());
			throw new LoginException("Invalid login attempt for user " + username);
		} catch (ProcessingException ex) {
			LOG.error("User {} could not authenticate due to an internal processing exception.  " +
					"Due to a Jersy bug, this may be due to a self-cert for the auth service.  " +
					"If running on a self-signed dev server, be sure to set the development " +
					"property to 'true' to allow self-signed certs.",
					"  Reason: {}", username, ex.getLocalizedMessage());
			throw ex;
		} finally {
			closeClientQuietly(client);
		}

		return result;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public AuthToken getToken(String tokenId) {
		Client client = createNewClient();
		AuthToken result = null;
		WebTarget target = client.target(this.authEndpointUri).
				path(ServicePaths.TOKEN).
				path(tokenId);

		try {
			result = target.request(MediaType.APPLICATION_JSON_TYPE).get(AuthToken.class);
		} catch (ClientErrorException ex) {
			LOG.info(MessageFormat.format("An error occurred while trying to get roles for token {0}", tokenId), ex);
			if(ex.getResponse().getStatus() == Response.Status.FORBIDDEN.getStatusCode() || 
					ex.getResponse().getStatus() == Response.Status.UNAUTHORIZED.getStatusCode()|| 
							ex.getResponse().getStatus() == Response.Status.NOT_FOUND.getStatusCode()) {
				throw new NotAuthorizedException(ex.getMessage());
			}
		} finally {
			closeClientQuietly(client);
		}

		return result;
	}
	
	@Override
	/**
	 * {@inheritDoc}
	 */
	public List<String> getRolesByToken(String tokenId) {
		Client client = createNewClient();
		List<String> result = null;
		WebTarget target = client.target(this.authEndpointUri).
				path(ServicePaths.TOKEN).
				path(tokenId).
				path(ServicePaths.ROLES);

		try {
			String response = target.request(MediaType.APPLICATION_JSON_TYPE).get(String.class);
			result = new Gson().fromJson(response, new TypeToken<List<String>>(){}.getType());
		} catch (ClientErrorException ex) {
			LOG.info(MessageFormat.format("An error occurred while trying get roles for token {0}", tokenId), ex);
		} finally {
			closeClientQuietly(client);
		}

		return result;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean invalidateToken(String tokenId) {
		boolean deleted = false;

		Client client = createNewClient();
		WebTarget target = client.target(this.authEndpointUri).
				path(ServicePaths.TOKEN).
				path(tokenId);

		try {
			Response response = target.request(MediaType.APPLICATION_JSON_TYPE).delete();
			int statusCode = response.getStatus();
			if (statusCode == Status.OK.getStatusCode()) {
				LOG.info("Invalidated token {}", tokenId);
				deleted = true;
			} else {
				LOG.info("Could not invalidate token {}. Error Code: {}, Reason: {}", tokenId, statusCode, response.getStatusInfo().getReasonPhrase());
			}
		} catch (ClientErrorException ex) {
			LOG.info(String.format("An error occurred while trying to delete token %s", tokenId), ex);
		} finally {
			closeClientQuietly(client);
		}

		return deleted;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean invalidateToken(AuthToken token) {
		return invalidateToken(token.getTokenId());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isValidToken(String tokenId) {
		boolean isValid;

		if (StringUtils.isBlank(tokenId)) {
			LOG.trace("Token id was blank or null when checking for validity.");
			isValid = false;
		} else {
			LOG.trace("Attempting to get token {} from server to check for validity.", tokenId);
			AuthToken token = getToken(tokenId);

			if (token != null) {
				LOG.trace("Token {} found on server. Checking for validity.", tokenId);
				isValid = isValidToken(token);
			} else {
				LOG.trace("Token {} not found on server.", tokenId);
				isValid = false;
			}
		}
		return isValid;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isValidToken(AuthToken token) {
		boolean isValid = true;

		if (token == null) {
			LOG.trace("Token was null when checking for validity.");
			isValid = false;
		} else if (token.isExpired()) {
			LOG.trace("Token {} has expired.", token.getTokenId());
			isValid = false;
		}

		return isValid;
	}

	protected void closeClientQuietly(Client client) {
		try {
			if (client != null) {
				client.close();
			}
		} catch (Exception ex) {
			LOG.debug("Client couldn't be closed", ex);
		}
	}
	
	/**
	 * If in a development environment, will try to create a relaxed client that 
	 * will not check self-signed SSL certificate validation. 
	 * 
	 * Otherwise, a regular, signature checking client is created.
	 * 
	 * If any errors are encountered during the creation of the relaxed client,
	 * a regular client is created.
	 * 
	 * @return 
	 */
	protected Client createNewClient() {
		if (isDevelopment) {
			return SSLTool.getRelaxedSSLClient();
		} else {
			return ClientBuilder.newClient();
		}
	}

}
