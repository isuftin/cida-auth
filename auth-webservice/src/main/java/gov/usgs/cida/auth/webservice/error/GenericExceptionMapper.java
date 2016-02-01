package gov.usgs.cida.auth.webservice.error;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

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

	public Response toResponse(Exception ex) {
		Response.Status code = Response.Status.FORBIDDEN;
		return Response.status(code).entity("{ \"error\": \"" + ex.getClass().getSimpleName() + " - " +
				ex.getMessage() + "\" }").type(MediaType.APPLICATION_JSON).build();
	}
}
