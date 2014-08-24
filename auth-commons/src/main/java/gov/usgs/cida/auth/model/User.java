package gov.usgs.cida.auth.model;

import java.util.Date;
import java.util.List;

import javax.naming.directory.DirContext;

public class User {

	private boolean isAuthenticated;

	private String username;

	private String email;

	private String givenName;

	private List<String> roles;

	private Date authenticatedTime;

	private Date lastAccessed;

	private DirContext dirContext;

	public List<String> getRoles() {
		return roles;
	}

	/**
	 * @param inRoles
	 */
	public void setRoles(final List<String> inRoles) {
		this.roles = inRoles;
	}

	public Date getAuthenticatedTime() {
		return authenticatedTime;
	}

	public void setAuthenticatedTime(Date authenticatedTime) {
		this.authenticatedTime = authenticatedTime;
	}

	public Date getLastAccessed() {
		return lastAccessed;
	}

	public void setLastAccessed(Date lastAccessed) {
		this.lastAccessed = lastAccessed;
	}

	public void setAuthenticated(boolean authenticated) {
		this.isAuthenticated = authenticated;
	}

	public boolean isAuthenticated() {
		return isAuthenticated;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getGivenName() {
		return givenName;
	}

	public void setGivenName(String givenName) {
		this.givenName = givenName;
	}

	public DirContext getDirContext() {
		return dirContext;
	}

	public void setDirContext(DirContext dirContext) {
		this.dirContext = dirContext;
	}
}
