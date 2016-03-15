package gov.usgs.cida.auth.service.authentication;

import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.dao.IAuthTokenDAO;
import gov.usgs.cida.auth.exception.NotAuthorizedException;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;
import gov.usgs.cida.auth.util.ConfigurationLoader;

public class CidaActiveDirectoryTokenService implements IAuthTokenService {
	private final static Logger LOG = LoggerFactory.getLogger(CidaActiveDirectoryTokenService.class);
	
	private IAuthTokenDAO authTokenDao;
	private IAuthService authService;
	
	public CidaActiveDirectoryTokenService() {
		authTokenDao = new AuthTokenDAO();
		authService = new LDAPService();
	}
	
	//For testability
	public CidaActiveDirectoryTokenService(IAuthTokenDAO authTokenDao, IAuthService authService) {
		this.authTokenDao = authTokenDao;
		this.authService = authService;
	}
	
	//For testing, can replace later with IOC/DI
	protected void setAuthTokenDao(IAuthTokenDAO authTokenDao) {
		this.authTokenDao = authTokenDao;
	}
	protected void setAuthService(IAuthService authService) {
		this.authService = authService;
	}
	
	@Override
	public AuthToken authenticate(String username, char[] password) throws NotAuthorizedException {
		
		User user = authService.authenticate(username, password);
		loadRoles(user, AuthenticationRoles.AD_AUTHENTICATED.toString(), authTokenDao);

		LOG.debug("User {} has authenticated", user.getUsername());
		
		if (user.isAuthenticated()) {
			AuthToken token = authTokenDao.create(user, ConfigurationLoader.getTtlSeconds());
			return token;
		} else {
			throw new NotAuthorizedException();
		}
	}
	
	/**
	* ***NOTE***, these roles are NOT restricted by domain (eg: johndoe@usgs.gov will get 
	* the roles of johndoe@gmail.com), this is OK *as long as* the authentication mechanism 
	* remains known and is restricted to the domain the roles manager expects.
	*/
	public static void loadRoles(User user, String authenticationMethod, IAuthTokenDAO authTokenDao) {
		ArrayList<String> newRoles = new ArrayList<>();
		newRoles.addAll(authTokenDao.getRoles(user.getUsername()));
		newRoles.add(authenticationMethod);
		user.setRoles(newRoles);
	}
}
