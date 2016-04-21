package gov.usgs.cida.auth.client.springsecurity;

import gov.usgs.cida.auth.client.IAuthClient;
import gov.usgs.cida.auth.model.AuthToken;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.login.LoginException;
import javax.ws.rs.WebApplicationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * This is a minimal implementation of AuthenticationProvider
 * This just delegates to a CIDA IAuthClient implementation for authentication
 * and provisioning.  The IAuthClient is wired in by the Spring configuration.
 * 
 * Note:  See the src/sample directory for an example of how to use this within
 * a Spring app.
 * 
 * @author eeverman
 */
@Component
public class CidaAuthenticationProvider implements AuthenticationProvider {
	private static final Logger LOG = LoggerFactory.getLogger(CidaAuthenticationProvider.class);
	
	protected IAuthClient authClient;
	
	@Autowired
	public CidaAuthenticationProvider(final IAuthClient authClient) {
		this.authClient = authClient;
	}
	
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = authentication.getName();
        String password = authentication.getCredentials().toString();
		
		AuthToken token = null;
		
		try {
			token = authClient.getNewToken(name, password);
		} catch (LoginException ex) {
			throw new BadCredentialsException("Invalid username or password");
		} catch (WebApplicationException ex) {
			LOG.error("Unable to process authentication request", ex);
			throw new InternalAuthenticationServiceException(
					"There was an intenal error while trying to authenticate.  " +
					"If this persists, please contact the system administrator.");
		}
		
		if (null == token || null == token.getTokenId() || token.getTokenId().isEmpty()) {
			throw new BadCredentialsException("Invalid username/password");
		}
		
		List<String> roles = authClient.getRolesByToken(token.getTokenId());
		List<GrantedAuthority> grantedAuths = new ArrayList();
		
		for (String role : roles) {
			grantedAuths.add(new SimpleGrantedAuthority(role));
		}
		
		Authentication auth = new UsernamePasswordAuthenticationToken(name, password, grantedAuths);
		
		return auth;
    }

	
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
