package gov.usgs.cida.auth.webservice.token;

import gov.usgs.cida.auth.service.ServicePaths;
import gov.usgs.cida.auth.webservice.error.ExpiredTokenExceptionMapper;
import gov.usgs.cida.auth.webservice.error.GenericExceptionMapper;

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
		classes.add(TokenWebService.class);
		
		//error provider
		classes.add(ExpiredTokenExceptionMapper.class);
		classes.add(GenericExceptionMapper.class);

		return classes;
	}
}
