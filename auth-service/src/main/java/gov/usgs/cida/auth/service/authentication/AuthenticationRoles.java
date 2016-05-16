package gov.usgs.cida.auth.service.authentication;

/**
 * These are roles that are given to a user depending on their authentication method.
 * 
 * @author thongsav
 *
 */
public enum AuthenticationRoles {
	AD_AUTHENTICATED,
	OAUTH_AUTHENTICATED,
	SAML_AUTHENTICATED,
	MANAGED_SERVICE_AUTHENTICATED
}
