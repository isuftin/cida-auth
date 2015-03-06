package gov.usgs.cida.auth.service.authentication;

import gov.usgs.cida.auth.model.User;

public interface IAuthService {
	public User authenticate(String username, char[] password);
}
