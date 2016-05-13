package gov.usgs.cida.auth.webservice.authentication;

import gov.usgs.cida.auth.exception.NotAuthorizedException;
import gov.usgs.cida.auth.exception.UntrustedRedirectException;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.service.ServicePaths;
import gov.usgs.cida.auth.service.authentication.CidaActiveDirectoryTokenService;
import gov.usgs.cida.auth.service.authentication.IAuthTokenService;
import gov.usgs.cida.auth.service.authentication.ManagedAuthTokenService;
import gov.usgs.cida.auth.service.authentication.OAuthService;
import gov.usgs.cida.auth.service.authentication.SamlService;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;

import javax.naming.NamingException;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

@Path("/")
public class AuthenticationWebervice {
	private final static Logger LOG = LoggerFactory.getLogger(AuthenticationWebervice.class);

	private IAuthTokenService cidaActiveDirectoryAuthTokenService = new CidaActiveDirectoryTokenService();
	private IAuthTokenService managedAuthTokenService = new ManagedAuthTokenService();
	private OAuthService oAuthService = new OAuthService();
	private SamlService samlService = new SamlService();
	
	@POST
	@Path(ServicePaths.AD + "/" + ServicePaths.TOKEN)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doAdAuth(
			@FormParam("username") String username,
			@FormParam("password")
			@DefaultValue("") String password) throws NamingException {
		LOG.trace("User {} is attempting to authenticate", username);
		return getADResponse(cidaActiveDirectoryAuthTokenService, username, password.toCharArray());
	}
	
	@POST
	@Path(ServicePaths.MANAGED + "/" + ServicePaths.TOKEN)
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doManagedAuth(
			@FormParam("username") String username,
			@FormParam("password")
			@DefaultValue("") String password) throws NamingException {
		LOG.trace("User {} is attempting to authenticate", username);
		return getADResponse(managedAuthTokenService, username, password.toCharArray());
	}
	
	@GET
	@Path(ServicePaths.OAUTH + "/" + ServicePaths.OAUTH_BEGIN)
	public Response redirectOauth(@QueryParam("successUrl") String successUrl,
			@QueryParam("redirectTemplate") String redirectTemplate) throws NamingException, URISyntaxException, UnsupportedEncodingException, UntrustedRedirectException {
		URI targetURIForRedirection = new URI(oAuthService.buildOauthTargetRequest(successUrl, redirectTemplate));
		return Response.seeOther(targetURIForRedirection).build();
	}
	
	@GET
	@Path(ServicePaths.OAUTH + "/" + ServicePaths.OAUTH_SUCCESS)
	public Response acceptOauthResponse(@QueryParam("code") String code, @QueryParam("state") String state) throws NamingException, URISyntaxException, NotAuthorizedException {
		URI targetURIForRedirection = new URI(oAuthService.authorize(code, state));
		return Response.seeOther(targetURIForRedirection).build();
	}
	
	@GET
	@Path(ServicePaths.SAML + "/" + ServicePaths.SAML_BEGIN)
	public Response redirectSaml(@QueryParam("successUrl") String successUrl,
			@QueryParam("redirectTemplate") String redirectTemplate,
			@QueryParam("serviceProviderId") String serviceProviderId) throws NamingException, URISyntaxException, UnsupportedEncodingException, UntrustedRedirectException {
		URI targetURIForRedirection = new URI(samlService.buildSamlTargetRequest(successUrl, redirectTemplate, serviceProviderId));
		return Response.seeOther(targetURIForRedirection).build();
	}
	
	@POST
	@Path(ServicePaths.SAML + "/" + ServicePaths.SAML_SUCCESS)
	public Response acceptSamlResponse(@FormParam("SAMLResponse") final String samlResponse) throws NamingException, URISyntaxException, NotAuthorizedException, CertificateException, KeyStoreException, ParserConfigurationException, SAXException, IOException, UnmarshallingException, ValidationException, javax.security.cert.CertificateException {
		URI targetURIForRedirection = new URI(samlService.authorize(samlResponse));
		return Response.seeOther(targetURIForRedirection).build();
	}

	/**
	 * Authenticates, creates token, generates proper Response
	 *
	 * @param username
	 * @param password
	 * @return
	 */
	protected Response getADResponse(IAuthTokenService authTokenService, String username, char[] password) {
		Response response;
		
		try {
			AuthToken token = authTokenService.authenticate(username, password);
			LOG.trace("Added token {} to database", token.getTokenId());
			response = Response.ok(token.toJSON(), MediaType.APPLICATION_JSON_TYPE).build();
		} catch (NotAuthorizedException e) {
			LOG.debug("User {} could not authenticate", username);
			response = Response.status(Response.Status.UNAUTHORIZED).build();
		}
		
		return response;
	}
}
