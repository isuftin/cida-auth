package gov.usgs.cida.auth.service.authentication;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.repackaged.org.apache.commons.codec.binary.Base64;
import com.google.api.client.repackaged.org.apache.commons.codec.binary.StringUtils;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.dao.IAuthTokenDAO;
import gov.usgs.cida.auth.exception.NotAuthorizedException;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;
import gov.usgs.cida.config.DynamicReadOnlyProperties;

/**
 * https://developers.google.com/identity/protocols/OpenIDConnect?hl=en#exchangecode
 * @author thongsav
 *
 */
public class OAuthService {
	private static final Logger LOG = LoggerFactory.getLogger(OAuthService.class);
	
	public static final String OAUTH_AUTHENTICATED_BASE_ROLE = "DOI_OAUTH_AUTHENTICATED";

	private static final String JNDI_OATH_URL_PARAM_NAME = "auth.oauth.endpoint";
	private static final String JNDI_CLIENT_ID_PARAM_NAME = "auth.oauth.client.id";
	private static final String JNDI_CLIENT_SECRET_PARAM_NAME = "auth.oath.client.secret";
	private static final String JNDI_SUCCESS_URL_PARAM_NAME = "auth.oauth.success.handler";
	private static final String JNDI_REQUIRED_DOMAIN_PARAM_NAME = "auth.oauth.required.domain";

	private static final String CIDA_AUTH_TEMPLATE_REPLACEMENT_STRING = "{cida_auth_token}";

	private static final int DATA_TTL = 300000; //data only kept around for 5 minutes
	private static final Cache<String, String> inProgressState = 
			CacheBuilder.newBuilder().expireAfterWrite(DATA_TTL, TimeUnit.MILLISECONDS).build();

	private String url;
	private String clientId;
	private String clientSecret;
	private String successUrl;
	private String requiredDomain;

	private IAuthTokenDAO authTokenDao; 
	
	public OAuthService() {
		authTokenDao = new AuthTokenDAO();
		
		DynamicReadOnlyProperties props = new DynamicReadOnlyProperties();
		try {
			props.addJNDIContexts();
		} catch (NamingException ex) {
			LOG.error("Error attempting to read JNDI properties.", ex);
		}

		url = props.getProperty(JNDI_OATH_URL_PARAM_NAME);
		clientId = props.getProperty(JNDI_CLIENT_ID_PARAM_NAME);
		clientSecret = props.getProperty(JNDI_CLIENT_SECRET_PARAM_NAME);
		successUrl = props.getProperty(JNDI_SUCCESS_URL_PARAM_NAME);
		requiredDomain = props.getProperty(JNDI_REQUIRED_DOMAIN_PARAM_NAME);
	}

	public String buildOauthTargetRequest(String redirectTemplate) throws UnsupportedEncodingException {
		String state = UUID.randomUUID().toString();
		inProgressState.asMap().put(state, redirectTemplate);

		StringBuilder fullUrl = new StringBuilder();
		fullUrl.append(url)
		.append("?response_type=code")
		.append("&state=").append(state)
		.append("&client_id=").append(URLEncoder.encode(clientId, "UTF-8"))
		.append("&scope=openid+profile+email")
		.append("&redirect_uri=").append(URLEncoder.encode(successUrl, "UTF-8"));
		return fullUrl.toString();
	}

	public String authorize(String code, String state) throws NotAuthorizedException {
		//Build final redirect URL and confirm state parameter for anti-forgery protection
		String redirectUrl = inProgressState.asMap().get(state);
		if(redirectUrl == null) { //not valid unless this state ID has been registered here recently by buildOauthTargetRequest
			throw new NotAuthorizedException();
		}

		//Use code to pull down ID
		Map<String, String> idToken = null;
		try {
			idToken =  getIdTokenAsMap(code);
			
			String email = idToken.get("email");
			String name = idToken.get("name");
			
			String username = email.split("@")[0];
			String hostedDomain = email.split("@")[1];
			
			//TODO may want a more robust way to handle this, currently can only restrict to one domain
			//if at all. A bit of a hack until we figure out what DOI's plans are for
			//offering their own OAUTH provider
			if(requiredDomain != null && !hostedDomain.endsWith(requiredDomain)) {
				throw new NotAuthorizedException();
			}
			
			User user = new User();
			user.setUsername(username);
			user.setGivenName(name);
			user.setEmail(email);
			user.setAuthenticated(true);
			user.setRoles(Arrays.asList(new String[] { OAUTH_AUTHENTICATED_BASE_ROLE }));
			AuthToken token = authTokenDao.create(user);
			
			redirectUrl = redirectUrl.replace(CIDA_AUTH_TEMPLATE_REPLACEMENT_STRING, token.getTokenId());
		} catch (IOException e) {
			throw new NotAuthorizedException();
		}
		
		return redirectUrl;
	}

	private Map<String, String> getIdTokenAsMap(String code) throws IOException {
		GoogleTokenResponse response =
				new GoogleAuthorizationCodeTokenRequest(new NetHttpTransport(), new JacksonFactory(),
						clientId, clientSecret, code, successUrl)
				.setScopes(Arrays.asList(new String[]{ "openid", "profile", "email"}))
				.execute();
					
		String[] base64EncodedSegments = response.getIdToken().split("\\.");
		String base64EncodedClaims = base64EncodedSegments[1];
		
		return new Gson().fromJson(StringUtils.newStringUtf8(Base64.decodeBase64(base64EncodedClaims)), 
				Map.class);
	}
}
