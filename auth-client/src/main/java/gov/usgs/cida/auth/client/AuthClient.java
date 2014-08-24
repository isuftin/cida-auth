package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.service.ServicePaths;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@inheritDoc}
 *
 * @author thongsav
 */
public class AuthClient implements IAuthClient {

	private static final Logger LOG = LoggerFactory.getLogger(AuthClient.class);
	final URI authEndpointUri;
	final URI getNewTokenPath;
	final URI getTokenPath;

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

		this.authEndpointUri = new URIBuilder(_authEndpoint).build();
		this.getNewTokenPath = new URIBuilder(_authEndpoint + ServicePaths.AUTHENTICATION + "/" + ServicePaths.AD + "/" + ServicePaths.TOKEN).build();
		this.getTokenPath = new URIBuilder(_authEndpoint + ServicePaths.TOKEN).build();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AuthToken getNewToken(String username, String password) {
		HttpPost post = new HttpPost(getNewTokenPath);
		AuthToken result = null;
		List<NameValuePair> nvps = new ArrayList<>();
		nvps.add(new BasicNameValuePair("username", username));
		nvps.add(new BasicNameValuePair("password", password));
		post.setEntity(new UrlEncodedFormEntity(nvps, Charset.defaultCharset()));

		try (CloseableHttpClient httpclient = HttpClients.createDefault();
				CloseableHttpResponse response = httpclient.execute(post)) {
			HttpEntity responseEntity = response.getEntity();
			StatusLine statusLine = response.getStatusLine();
			int statusCode = statusLine.getStatusCode();

			if (statusCode == 200) {
				String authTokenString = IOUtils.toString(responseEntity.getContent());
				result = AuthToken.fromJSON(authTokenString);
			} else {
				LOG.info("User {} could not authenticate. Error Code: {}, Reason: {}", username, statusCode, statusLine.getReasonPhrase());
			}
			EntityUtils.consume(responseEntity);
		} catch (IOException ex) {
			LOG.warn("An error occurred while calling auth service", ex);
		}
		return result;
	}

	@Override
	public AuthToken getToken(String tokenId) {
		AuthToken result = null;
		URI tokenPath = null;

		try {
			tokenPath = new URIBuilder(String.format("%s/%s", this.getTokenPath.toASCIIString(), tokenId)).build();
		} catch (URISyntaxException ex) {
			LOG.warn("Could not create proper URI from token path", ex);
		}

		if (tokenPath != null) {
			HttpGet get = new HttpGet(tokenPath);
			try (CloseableHttpClient httpclient = HttpClients.createDefault();
					CloseableHttpResponse response = httpclient.execute(get)) {
				HttpEntity responseEntity = response.getEntity();
				StatusLine statusLine = response.getStatusLine();
				int statusCode = statusLine.getStatusCode();

				if (statusCode == 200) {
					String authTokenString = IOUtils.toString(responseEntity.getContent());
					result = AuthToken.fromJSON(authTokenString);
					LOG.debug("Retrieved token {} from server.", tokenId);
				} else {
					LOG.info("Could not get token {}. Error Code: {}, Reason: {}", tokenId, statusCode, statusLine.getReasonPhrase());
				}
				EntityUtils.consume(responseEntity);
			} catch (IOException ex) {
				LOG.warn(MessageFormat.format("An error occurred while trying to get token {0}", tokenId), ex);
			}
		}

		return result;
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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean invalidateToken(AuthToken token) {
		return invalidateToken(token.getTokenId());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean invalidateToken(String tokenId) {
		URI tokenPath = null;
		boolean deleted = false;

		try {
			tokenPath = new URIBuilder(String.format("%s/%s", this.getTokenPath.toASCIIString(), tokenId)).build();
		} catch (URISyntaxException ex) {
			LOG.warn("Could not create proper URI from token path", ex);
		}
		if (tokenPath != null) {
			HttpDelete delete = new HttpDelete(tokenPath);
			try (CloseableHttpClient httpclient = HttpClients.createDefault();
					CloseableHttpResponse response = httpclient.execute(delete)) {
				StatusLine statusLine = response.getStatusLine();
				int statusCode = statusLine.getStatusCode();
				if (statusCode == 200) {
					LOG.info("Invalidated token {}", tokenId);
					deleted = true;
				} else {
					LOG.info("Could not invalidate token {}. Error Code: {}, Reason: {}", tokenId, statusCode, statusLine.getReasonPhrase());
				}
			} catch (IOException ex) {
				LOG.warn(String.format("An error occurred while trying to delete token %s", tokenId), ex);
			}
		}
		return deleted;
	}

}
