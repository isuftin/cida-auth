package gov.usgs.cida.auth.service.authentication;

import gov.usgs.cida.auth.model.User;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class ManagedService {

	private static final Logger LOG = LoggerFactory.getLogger(ManagedService.class);
	
	// basic auth hash for crowd app, using DatatypeConverter.printBase64Binary
	public static final String BASIC_AUTH = "BASIC Y2lkYTpkZ3h2eHZQRA==";
	public static final String CROWD_BASE_URL = "https://my.usgs.gov/crowd/rest/usermanagement/latest";

	private ManagedService() {
		// Utility class, should not be instantiated
	}

	public static User authenticate(String username, char[] password) {
		User user = new User();
		user.setAuthenticated(false);
		
		Client client = ClientBuilder.newClient();
		WebTarget target = client.target(CROWD_BASE_URL).path("authentication");
		
		LOG.debug("target URI = " + target.getUri());
		
		Builder request = target.
				queryParam("username", username).
				request(MediaType.APPLICATION_JSON_TYPE).
				header("Authorization", BASIC_AUTH).
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
			throw new NotAuthorizedException(resultText);
		}
		
		if (user.isAuthenticated()) {
			target = client.target(CROWD_BASE_URL).path("user").path("group").path("direct");
			request = target.
					queryParam("username", username).
					request(MediaType.APPLICATION_JSON_TYPE).
					header("Authorization", BASIC_AUTH);

			result = request.get();
			resultText = result.readEntity(String.class);

			LOG.debug("custom authorize request result = " + result.getStatus());
			LOG.debug(resultText);
			
			if (Status.OK.getStatusCode() == result.getStatus()) {
				JsonElement element = new JsonParser().parse(resultText);
				JsonArray groups = element.getAsJsonObject().getAsJsonArray("groups");
				List<String> roles = new ArrayList<String>();
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
