package gov.usgs.cida.auth.service.authentication;

import gov.usgs.cida.auth.model.User;
import gov.usgs.cida.config.DynamicReadOnlyProperties;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class ManagedAuthService  implements IAuthService{

	private static final Logger LOG = LoggerFactory.getLogger(ManagedAuthService.class);
	
	private static final String JNDI_BASIC_AUTH_PARAM_NAME = "auth.http.basic";
	private static final String JNDI_CROWD_URL_PARAM_NAME = "auth.crowd.url";

	public ManagedAuthService() {
	}
	
	public User authenticate(String username, char[] password) {
		User user = new User();
		user.setAuthenticated(false);

		DynamicReadOnlyProperties props = new DynamicReadOnlyProperties();
		try {
			props.addJNDIContexts();
		} catch (NamingException ex) {
			LOG.error("Error attempting to read JNDI properties.", ex);
		}
		
		String basicAuth = props.getProperty(JNDI_BASIC_AUTH_PARAM_NAME);
		String url = props.getProperty(JNDI_CROWD_URL_PARAM_NAME);
		if (StringUtils.isBlank(basicAuth) || StringUtils.isBlank(url)) {
			LOG.error("Error authenticating against Crowd. Check that JNDI parameters are configured.");
		} else {
			user = authenticate(username, password, basicAuth, url);
		}
		
		return user;
	}
	
	private User authenticate(String username, char[] password, String basicAuth, String url) {
		User user = new User();
		user.setAuthenticated(false);
		
		Client client = ClientBuilder.newClient();
		WebTarget target = client.target(url).path("authentication");
		
		LOG.debug("target URI = " + target.getUri());
		
		Builder request = target.
				queryParam("username", username).
				request(MediaType.APPLICATION_JSON_TYPE).
				header("Authorization", basicAuth).
				header("Content-Type", MediaType.APPLICATION_JSON);
		
		Response result = request.post(Entity.json("{ \"value\" : \"" + String.valueOf(password) + "\" }"));
		String resultText = result.readEntity(String.class);
		
		LOG.debug("custom authenticate request result = " + result.getStatus());
		LOG.debug(resultText);
		
		if (Status.OK.getStatusCode() == result.getStatus()) {
			JsonElement element = new JsonParser().parse(resultText);
			JsonObject object = element.getAsJsonObject();
			user.setUsername(object.getAsJsonPrimitive("name").getAsString());
			user.setGivenName(object.getAsJsonPrimitive("display-name").getAsString());
			user.setEmail(object.getAsJsonPrimitive("email").getAsString());
			user.setAuthenticated(true);
		} else {
			user.setAuthenticated(false);
			return user;
		}
		
		if (user.isAuthenticated()) {
			target = client.target(url).path("user").path("group").path("direct");
			request = target.
					queryParam("username", username).
					request(MediaType.APPLICATION_JSON_TYPE).
					header("Authorization", basicAuth);

			result = request.get();
			resultText = result.readEntity(String.class);

			LOG.debug("custom authorize request result = " + result.getStatus());
			LOG.debug(resultText);
			
			if (Status.OK.getStatusCode() == result.getStatus()) {
				JsonElement element = new JsonParser().parse(resultText);
				JsonArray groups = element.getAsJsonObject().getAsJsonArray("groups");
				List<String> roles = new ArrayList<>();
				for (int i = 0; i < groups.size(); i++) {
					String groupName = groups.get(i).getAsJsonObject().getAsJsonPrimitive("name").getAsString();
					LOG.debug("adding group: " + groupName);
					roles.add(groupName);
				}
				user.setRoles(roles);
			}
		}

		client.close();
		
		return user;
	}

}
