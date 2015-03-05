package gov.usgs.cida.auth.webservice.error;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

/**
 * Handlers and reports ExpiredTokenException. See
 * {@link gov.usgs.cida.auth.webservice.error.ExpiredTokenException}
 *
 * @author thongsav
 *
 *
 */
@Provider
public class ExpiredTokenExceptionMapper implements
		ExceptionMapper<ExpiredTokenException> {

	public Response toResponse(ExpiredTokenException ex) {
		Response.Status code = Response.Status.FORBIDDEN;
		return Response.status(code).entity(ex.getMessage()).type(MediaType.TEXT_PLAIN).build();
	}
}
