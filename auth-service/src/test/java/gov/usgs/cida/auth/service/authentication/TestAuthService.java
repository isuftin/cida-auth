package gov.usgs.cida.auth.service.authentication;

import gov.usgs.cida.auth.model.User;

public class TestAuthService implements IAuthService {

	@Override
	public User authenticate(String username, char[] password) {
		User user = new User();
		user.setUsername(username);
		
		if(username.equals("validUser") && String.valueOf(password).equals("validPassword")) {
			user.setAuthenticated(true);
		} else {
			user.setAuthenticated(false);
		}
			
		return user;
	}

}
