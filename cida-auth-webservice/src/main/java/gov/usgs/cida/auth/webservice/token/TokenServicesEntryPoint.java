package gov.usgs.cida.auth.webservice.token;

import gov.usgs.cida.auth.service.ServicePaths;
import java.util.HashSet;
import java.util.Set;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 *
 * @author isuftin
 */
@ApplicationPath("/" + ServicePaths.TOKEN)
public class TokenServicesEntryPoint extends Application {

	@Override
	public Set<Class<?>> getClasses() {
		final Set<Class<?>> classes = new HashSet<>();

		// webservices
		classes.add(TokenService.class);

		return classes;
	}
}
