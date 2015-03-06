package gov.usgs.cida.auth.service.authentication;

import gov.usgs.cida.auth.exception.NotAuthorizedException;
import gov.usgs.cida.auth.model.AuthToken;

public interface IAuthTokenService {
	public AuthToken authenticate(String username, char[] password) throws NotAuthorizedException;
}
