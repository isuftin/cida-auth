package gov.usgs.cida.auth.webservice.error;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handlers and reports ExpiredTokenException. See
 * {@link gov.usgs.cida.auth.exception.ExpiredTokenException}
 *
 * @author thongsav
 *
 *
 */
@Provider
public class GenericExceptionMapper implements
		ExceptionMapper<Exception> {
	private final static Logger LOG = LoggerFactory.getLogger(GenericExceptionMapper.class);

	public Response toResponse(Exception ex) {
		String serviceId = String.valueOf(System.currentTimeMillis());
		
		LOG.error("Auth Webservice error #" + serviceId + ": " + ex.getMessage(), ex);
		
		Response.Status code = Response.Status.FORBIDDEN;
		return Response.status(code).entity("{ \"error\": \"" + ex.getClass().getSimpleName() + " - " +
				ex.getMessage() + "\", \"serviceId\": \"" + serviceId + "\" }").type(MediaType.APPLICATION_JSON).build();
	}
}
