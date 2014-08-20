package gov.usgs.cida.auth.webservice.authentication;

import java.util.HashSet;
import java.util.Set;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 *
 * @author isuftin
 */
@ApplicationPath("/auth")
public class AuthenticationServicesEntryPoint extends Application {

	@Override
	public Set<Class<?>> getClasses() {
		final Set<Class<?>> classes = new HashSet<>();

		// webservices
		classes.add(ActiveDirectoryService.class);

		return classes;
	}
}
