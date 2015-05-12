package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import javax.naming.Context;
import javax.naming.InitialContext;

import javax.naming.NamingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The purpose of this client is to implement the interface without 
 * requiring the user to actually authenticate.  This should only be used for
 * testing and development when authorization and authentication is not an issue.
 * IMPORTANT, this does not provide any security, you've been warned.
 * 
 * @author Jordan Walker <jiwalker@usgs.gov>
 */
public class NullAuthClient implements IAuthClient {
	
	private static final Logger LOG = LoggerFactory.getLogger(NullAuthClient.class);
	
	public static final String AUTH_ROLES_JNDI_NAME = "cida.auth.client.null.roles";
	public static final String AUTH_ROLES_DELIMITER = ",";
	
	private List<String> roles;
	
	public NullAuthClient() {
		roles = new ArrayList<>();
		try {
			Context ctx = new InitialContext();
			String delimitedRoles =  (String) ctx.lookup("java:comp/env/" + AUTH_ROLES_JNDI_NAME);
			if (delimitedRoles != null) {
				String[] split = delimitedRoles.split(AUTH_ROLES_DELIMITER);
				roles.addAll(Arrays.asList(split));
			}
		} catch (NamingException ex) {
			LOG.debug("JNDI name " + AUTH_ROLES_JNDI_NAME + "not set, users will have no roles assigned");
		}
	}
	
	@Override
	public AuthToken getNewToken(String username, String password) {
		AuthToken authToken = getToken(UUID.randomUUID().toString());
		return authToken;
	}

	@Override
	public AuthToken getToken(String tokenId) {
		AuthToken authToken = new AuthToken();
		authToken.setIssued(Timestamp.from(Instant.now()));
		authToken.setLastAccess(Timestamp.from(Instant.now()));
		authToken.setExpires(Timestamp.from(Instant.MAX));
		authToken.setRoles(roles);
		authToken.setTokenId(tokenId);
		authToken.setUsername("jdoe");
		return authToken;
	}

	@Override
	public List<String> getRolesByToken(String tokenId) {
		return roles;
	}

	@Override
	public boolean isValidToken(String tokenId) {
		return tokenId != null;
	}

	@Override
	public boolean isValidToken(AuthToken token) {
		if (token != null) {
			return isValidToken(token.getTokenId());
		} else {
			return false;
		}
	}

	@Override
	public boolean invalidateToken(AuthToken token) {
		return true;
	}

	@Override
	public boolean invalidateToken(String tokenId) {
		return true;
	}

}
