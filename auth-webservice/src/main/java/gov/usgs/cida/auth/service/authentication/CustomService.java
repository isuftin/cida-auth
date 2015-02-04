package gov.usgs.cida.auth.service.authentication;

import gov.usgs.cida.auth.model.User;

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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class CustomService {

	private static final Logger LOG = LoggerFactory.getLogger(CustomService.class);
	
	// created for iplover crowd app, using DatatypeConveter.printBase64Binary
	private static final String BASIC_AUTH = "BASIC aXBsb3ZlcjpkZ3h2eHZQRA==";
	private static final String CROWD_BASE_URL = "https://my.usgs.gov/crowd/rest/usermanagement/latest";

	private CustomService() {
		// Utility class, should not be instantiated
	}

	public static User authenticate(String username, String password) {
		User user = new User();
		user.setAuthenticated(false);
		
		LOG.debug("custom auth");
		
		String json = "{ \"value\" : \"" + password + "\" }";
		JsonObject postData = new JsonParser().parse(json).getAsJsonObject();
		
		LOG.debug("post json = " + postData);

		Client client = ClientBuilder.newClient();
		WebTarget target = client.target(CROWD_BASE_URL).path("authentication");
		
		LOG.debug("target URI = " + target.getUri());
		
		Builder request = target.
				queryParam("username", username).
				request(MediaType.APPLICATION_JSON_TYPE).
				header("Authorization", BASIC_AUTH).
				header("Content-Type", MediaType.APPLICATION_JSON);
		
		Response result = request.post(Entity.json(json));
		
		LOG.debug("basic auth = " + BASIC_AUTH);
		LOG.debug("custom auth request result = " + result.getStatus());
		String resultText = result.readEntity(String.class);
		LOG.debug(resultText);
		
		if(Status.OK.getStatusCode() == result.getStatus()) {
			JsonElement element = new JsonParser().parse(resultText);
			JsonObject object = element.getAsJsonObject();
			user.setUsername(object.getAsJsonPrimitive("name").getAsString());
			user.setGivenName(object.getAsJsonPrimitive("display-name").getAsString());
			user.setEmail(object.getAsJsonPrimitive("email").getAsString());
			user.setAuthenticated(true);
		} else {
			throw new NotAuthorizedException(resultText);
		}

		client.close();

		return user;
	}

}
