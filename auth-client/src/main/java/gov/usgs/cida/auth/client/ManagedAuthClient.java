package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.service.ServicePaths;

import java.net.URISyntaxException;

import javax.ws.rs.ClientErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@inheritDoc}
 */
public class ManagedAuthClient extends AuthClient {
	private static final Logger LOG = LoggerFactory.getLogger(ManagedAuthClient.class);
	
	public ManagedAuthClient(String authEndpoint) throws URISyntaxException {
		super(authEndpoint);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public AuthToken getNewToken(String username, String password) {
		Client client = createNewClient();
		AuthToken result = null;
		Form form = new Form();
		form.param("username", username);
		form.param("password", password);
		WebTarget target = client.target(this.authEndpointUri).
				path(ServicePaths.AUTHENTICATION).
				path(ServicePaths.MANAGED).
				path(ServicePaths.TOKEN);

		try {
			Entity<Form> postEntity = Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE);
			result = target.
					request(MediaType.APPLICATION_JSON_TYPE).
					post(postEntity, AuthToken.class);
		} catch (ClientErrorException ex) {
			LOG.info("User {} could not authenticate. Error Code: {}, Reason: {}", username, ex.getResponse().getStatus(), ex.getResponse().getStatusInfo().getReasonPhrase());
			if(ex.getResponse().getStatus() == Response.Status.FORBIDDEN.getStatusCode() || 
					ex.getResponse().getStatus() == Response.Status.UNAUTHORIZED.getStatusCode()) {
				throw new NotAuthorizedException(ex.getResponse());
			}
		} finally {
			closeClientQuietly(client);
		}

		return result;
	}

}
