package gov.usgs.cida.auth.ws.rs;

import java.security.Principal;
import java.util.List;

import javax.ws.rs.core.SecurityContext;

public class AuthSecurityContext implements SecurityContext{
	private List<String> roles;
	
	public AuthSecurityContext(String user, List<String> roles) {
		this.roles = roles;
	}
	
	@Override
	public boolean isUserInRole(String role) {
		return roles.contains(role);
	}

	@Override
	public Principal getUserPrincipal() {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public boolean isSecure() {
		// TODO Auto-generated method stub
		return false;
	}
	
	@Override
	public String getAuthenticationScheme() {
		// TODO Auto-generated method stub
		return null;
	}

}
