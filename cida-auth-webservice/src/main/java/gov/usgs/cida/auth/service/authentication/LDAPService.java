package gov.usgs.cida.auth.service.authentication;

import gov.usgs.cida.auth.model.User;
import java.util.Properties;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A service to interact with active directory
 *
 * @author isuftin
 */
public class LDAPService {

	private static final Logger LOG = LoggerFactory.getLogger(LDAPService.class);

	private static final String JNDI_LDAP_URL_PARAM_NAME = "auth/ldap/url";
	private static final String JNDI_LDAP_DOMAIN_PARAM_NAME = "auth/ldap/domain";

	private LDAPService() {
		// Utility class, should not be instantiated
	}

	public static User authenticate(String username, char[] password) {
		User user = new User();
		user.setAuthenticated(false);

		try {
			Context initCtx = new InitialContext();
			String url = (String) initCtx.lookup("java:comp/env/" + JNDI_LDAP_URL_PARAM_NAME);
			String domain = (String) initCtx.lookup("java:comp/env/" + JNDI_LDAP_DOMAIN_PARAM_NAME);
			user = authenticate(username, password, url, domain);
		} catch (NamingException e) {
			LOG.error("Error authenticating against LDAP. Check that JNDI parameters are configured", e);
		}

		return user;
	}

	/**
	 * Does the heavy lifting of authenticating against LDAP
	 *
	 * @param username
	 * @param password
	 * @param ldapUrl
	 * @param basedn
	 * @return
	 */
	private static User authenticate(String username, char[] password, String ldapUrl, String basedn) {
		//basedn should be "DC=gs,DC=doi,dc=net"
		Properties props = new Properties();
		props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		props.put(Context.PROVIDER_URL, ldapUrl);
		props.put(Context.REFERRAL, "ignore");
		props.put(Context.SECURITY_AUTHENTICATION, "simple");

		// set properties for authentication
		props.put(Context.SECURITY_PRINCIPAL, username + "@gs.doi.net");
		props.put(Context.SECURITY_CREDENTIALS, password);

		User user = new User();

		try {
			InitialDirContext context = new InitialDirContext(props);
			SearchControls ctrls = new SearchControls();
			ctrls.setReturningAttributes(new String[]{"dn", "mail", "givenname", "sn", "samaccountname"});
			ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
			NamingEnumeration<SearchResult> answers = context.search(
					basedn,
					"(samaccountname=" + username + ")",
					ctrls
			);
			if (answers.hasMore()) {
				SearchResult result = answers.next();
				Attributes attributes = result.getAttributes();
				String mail = (String) attributes.get("mail").get();
				String givenname = (String) attributes.get("givenname").get();
				String uid = (String) attributes.get("samaccountname").get();

				user.setUsername(uid);
				user.setEmail(mail);
				user.setGivenName(givenname);
				user.setAuthenticated(true);
				user.setDirContext(context);
			}
		} catch (NamingException ex) {
			LOG.debug("unable to authenticate user", ex);
		} finally {
			props.put(Context.SECURITY_CREDENTIALS, new char[0]);
		}

		return user;
	}
}
