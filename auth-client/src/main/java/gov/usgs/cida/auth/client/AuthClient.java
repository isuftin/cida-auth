package gov.usgs.cida.auth.client;

import gov.usgs.cida.auth.model.AuthToken;

import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * {@inheritDoc}
 * 
 * @author thongsav
 */
public class AuthClient implements IAuthClient {
	    
    private static final Logger LOG = LoggerFactory.getLogger(AuthClient.class);
    
    public AuthClient(URL AuthEndpoint) {
    }

	@Override
	/**
	 * {@inheritDoc}
	 */
	public AuthToken getNewToken(String username, String password) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean isValidToken(String token) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean isValidToken(AuthToken token) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean invalidateToken(AuthToken token) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	/**
	 * {@inheritDoc}
	 */
	public boolean invalidateToken(String token) {
		// TODO Auto-generated method stub
		return false;
	}
    
}
