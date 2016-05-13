package gov.usgs.cida.auth.service.authentication;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.naming.NamingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.xml.XMLConstants;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.impl.IDPSSODescriptorImpl;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import gov.usgs.cida.auth.dao.FederatedAuthDAO;
import gov.usgs.cida.auth.dao.IAuthTokenDAO;
import gov.usgs.cida.auth.dao.IFederatedAuthDAO;
import gov.usgs.cida.auth.exception.NotAuthorizedException;
import gov.usgs.cida.auth.exception.UntrustedRedirectException;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;
import gov.usgs.cida.auth.util.ConfigurationLoader;
import gov.usgs.cida.config.DynamicReadOnlyProperties;
/**
 * Coordinates SAML2.0 flow
 * 
 * @author thongsav
 *
 */
public class SamlService {
	private static final Logger LOG = LoggerFactory.getLogger(SamlService.class);

	private static final String JNDI_SAML_URL_PARAM_NAME = "auth.saml.redirect.endpoint";
	private static final String JNDI_SAML_METADATA_URL_PARAM_NAME = "auth.saml.metadata.endpoint";
	private static final String CIDA_AUTH_TEMPLATE_REPLACEMENT_STRING = "[cida_auth_token]";

	private static final int DATA_TTL = 60000; //data only kept around for 1 minutes
	private static final Cache<String, String> inProgressState = 
			CacheBuilder.newBuilder().expireAfterWrite(DATA_TTL, TimeUnit.MILLISECONDS).build();
	
	private static final String EMAIL_ATT_NAME = "EmailAddress";

	private String url;

	private IAuthTokenDAO authTokenDao; 
	private IFederatedAuthDAO federatedAuthDAO; 
	
	private String trustedSamlMetadataUrl;
	private X509Certificate trustedCertificate;
	private X509Certificate getTrustedCertificate() throws CertificateException, MetadataProviderException, IOException {
		if(trustedCertificate == null) {
			//retrieve metadata from IDP
			Client client = ClientBuilder.newClient();
			WebTarget target = client.target(trustedSamlMetadataUrl);
			try {
				String metadata = target.request(MediaType.APPLICATION_XML).get(String.class);
				trustedCertificate = getIdpSsoSigningCertificatedFromMetadata(metadata);
			} catch(Exception e) {
				LOG.warn("Could not get X509 certificate from metadata");
			}finally {
				try {
					if (client != null) {
						client.close();
					}
				} catch (Exception ex) {
				}
			}
		}
		return trustedCertificate;
	}
	
	public void setTrustedCertificate(X509Certificate cert) { //for unit testing
		trustedCertificate = cert;
	}

	public SamlService() {
		authTokenDao = new AuthTokenDAO();
		federatedAuthDAO = new FederatedAuthDAO();

		DynamicReadOnlyProperties props = new DynamicReadOnlyProperties();
		try {
			props.addJNDIContexts();
		} catch (NamingException ex) {
			LOG.error("Error attempting to read JNDI properties.", ex);
		}

		url = props.getProperty(JNDI_SAML_URL_PARAM_NAME);
		trustedSamlMetadataUrl = props.getProperty(JNDI_SAML_METADATA_URL_PARAM_NAME);
	}

	/**
	 * This builds a redirect URL with the proper SAML requst encoded into the query parameters to 
	 * initiate a SAML2 flow.
	 * 
	 * @param successUrl url which will handle the authenticated user's redirect 
	 * @param redirectTemplate a url template which will let us know where to forward the authenticated user back
	 * @param serviceProviderId the service provider id identifying which SAML application we are using
	 * @return
	 * @throws UntrustedRedirectException
	 */
	public String buildSamlTargetRequest(String successUrl, String redirectTemplate, String serviceProviderId) throws UntrustedRedirectException {
		if(!isAcceptedForwardUrl(redirectTemplate)) {
			throw new UntrustedRedirectException();
		}
		
		String state = UUID.randomUUID().toString();
		inProgressState.asMap().put(state, redirectTemplate);
		
		// Issuer object
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(serviceProviderId);

		// AuthnContextClass
		AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject(
				SAMLConstants.SAML20_NS,
				"AuthnContextClassRef", "saml");
		authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);

		// AuthnContext
		RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
		RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
		requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

		// Creation of AuthRequestObject
		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authnRequest = authRequestBuilder.buildObject();
		authnRequest.setID(serviceProviderId);
		authnRequest.setDestination(url);
		authnRequest.setVersion(SAMLVersion.VERSION_20);
		authnRequest.setForceAuthn(false);
		authnRequest.setIsPassive(false);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(successUrl);
		authnRequest.setProviderName(serviceProviderId);
		authnRequest.setIssuer(issuer);
		authnRequest.setRequestedAuthnContext(requestedAuthnContext);
		
		String requestUrl;
		try {
			DefaultBootstrap.bootstrap();
			Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(authnRequest);
			org.w3c.dom.Element authDOM = marshaller.marshall(authnRequest);
			StringWriter rspWrt = new StringWriter();
			XMLHelper.writeNode(authDOM, rspWrt);
			String encodedSamlRequest = samlEncode(rspWrt.toString());
			requestUrl = url + "?SAMLRequest=" + encodedSamlRequest + "&RelayState=" + state;
		} catch (MarshallingException | ConfigurationException | MessageEncodingException e) {
			throw new RuntimeException("could not serizlize SAML request");
		}
		

		return requestUrl;
	}

	/**
	 * This is the latter half of the SAML2.0 POST binding flow. The SAML IDP will post to this
	 * service with a response after the user has authenticated. This method validates the response
	 * and gets the user information from the response.
	 * 
	 * @param rawSamlResponseString
	 * @param relayState
	 * @return
	 * @throws NotAuthorizedException
	 */
	public String authorize(String rawSamlResponseString, String relayState) throws NotAuthorizedException {
		//Build final redirect URL and confirm state parameter for anti-forgery protection
		String redirectUrl = inProgressState.asMap().get(relayState);
		if(redirectUrl == null) { //not valid unless this relayState ID has been registered here recently by buildSamlTargetRequest
			throw new NotAuthorizedException();
		}
		
		try {
			//This will bring back the user information as well as validate signed assertions
			Response samlResponse = getAuthorizedResponse(rawSamlResponseString);
			
			String email = getEmailAddress(samlResponse);
			String username = email;
			
			if(isAcceptedDomain(email)) {
				User user = new User();
				user.setUsername(username);
				user.setEmail(email);
				user.setAuthenticated(true);
				
				//See comment on this method, roles are NOT restricted to user's domain.
				CidaActiveDirectoryTokenService.loadRoles(user, AuthenticationRoles.SAML_AUTHENTICATED.toString(), authTokenDao);
				
				AuthToken token = authTokenDao.create(user, ConfigurationLoader.getTtlSeconds());
				
				redirectUrl = redirectUrl.replace(CIDA_AUTH_TEMPLATE_REPLACEMENT_STRING, token.getTokenId());
			} else {
				redirectUrl = redirectUrl.replace(CIDA_AUTH_TEMPLATE_REPLACEMENT_STRING, ""); //forward with no token
			}
		} catch (ConfigurationException | SecurityException | CertificateException | KeyStoreException | 
				ParserConfigurationException | SAXException | IOException | UnmarshallingException | 
				ValidationException | javax.security.cert.CertificateException | MetadataProviderException e) {
			LOG.error("Could not verify SAML trust relationship", e);
			throw new NotAuthorizedException("Could not verify SAML trust relationship");
		}

		return redirectUrl;
	}
	
	/**
	 * Verify that SAML user is from a trusted domain.
	 * 
	 * @param email
	 * @return
	 */
	
	private boolean isAcceptedDomain(String email) {
		List<String> acceptedDomains = federatedAuthDAO.getAllAcceptedDomains();

		for(String d : acceptedDomains) {
			if(email.toLowerCase().endsWith("@" + d.toLowerCase())) {
				return true;
			}
		}

		return false;
	}
	
	/**
	 * Verify that the post-authentication URL is a trusted destination.
	 * 
	 * @param url
	 * @return
	 */
	private boolean isAcceptedForwardUrl(String url) {
		List<String> urls = federatedAuthDAO.getAllAcceptedForwardUrls();
		
		for(String u : urls) {
			if(url.toLowerCase().startsWith(u.toLowerCase())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * This parses the raw SAML response and does signature validation.
	 * 
	 * @param rawBase64EncodedSamlResponse
	 * @return
	 * @throws ConfigurationException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 * @throws UnmarshallingException
	 * @throws ValidationException
	 * @throws CertificateException
	 * @throws KeyStoreException
	 * @throws javax.security.cert.CertificateException
	 * @throws MetadataProviderException
	 */
	private Response getAuthorizedResponse(String rawBase64EncodedSamlResponse) throws ConfigurationException, ParserConfigurationException, SAXException, IOException, UnmarshallingException, ValidationException, CertificateException, KeyStoreException, javax.security.cert.CertificateException, MetadataProviderException {
		byte[] samlBytes = DatatypeConverter.parseBase64Binary(rawBase64EncodedSamlResponse);
		String xmlString = new String(samlBytes, "UTF-8");
		
		DefaultBootstrap.bootstrap();
		
		// Get parser pool manager
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware (true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		Element samlRootElement = builder.parse(new ByteArrayInputStream(xmlString.getBytes())).getDocumentElement();

		// Get apropriate unmarshaller
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlRootElement);

		// Unmarshall using the document root element
		Response response = (Response) unmarshaller.unmarshall(samlRootElement);

		Signature signature = response.getSignature();
		if (signature != null) {
			validateSignature(signature); //check if signed correctly
			LOG.debug("Response signature successfully validated!");
		}

		for(Assertion assertion : response.getAssertions()) {
			Signature assertionSignature = assertion.getSignature();
			if (assertionSignature != null) {
				//check if signed with our known and trusted cert
				validateSignature(assertionSignature, getTrustedCertificate());
				LOG.debug("Assertion signature successfully validated!");
			}
		}

		return response;
	}
	
	private String getEmailAddress(Response samlResponse) {
		for(Assertion assertion : samlResponse.getAssertions()) {
			for(AttributeStatement stmt : assertion.getAttributeStatements()) {
				for(Attribute att : stmt.getAttributes()) {
					if(att.getName().equals(EMAIL_ATT_NAME)) {
						return att.getAttributeValues().get(0).getDOM().getTextContent();
					}
				}
			}
		}
		
		return null;
	}

	/**
	 * Ensures the signature is valid against a known and trusted certificate.
	 * @param signature
	 * @param certificate
	 * @throws CertificateException
	 * @throws ValidationException
	 */
	private void validateSignature(Signature signature, X509Certificate certificate) throws CertificateException, ValidationException {
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(certificate);

		SignatureValidator signatureValidator = new SignatureValidator(credential);
		signatureValidator.validate(signature);
	}

	/**
	 * Ensures the signature is valid.
	 * 
	 * @param signature
	 * @throws CertificateException
	 * @throws ValidationException
	 */
	private void validateSignature(Signature signature) throws CertificateException, ValidationException {
		org.opensaml.xml.signature.X509Certificate openSamlCertificate = getCertificateFromSignature(signature);

		X509Certificate certificate = KeyInfoHelper.getCertificate(openSamlCertificate);

		validateSignature(signature, certificate);
	}

	/**
	 * Retrieves certificate from signature for validation.
	 * 
	 * @param signature
	 * @return
	 */
	private org.opensaml.xml.signature.X509Certificate getCertificateFromSignature(Signature signature) {
		KeyInfo keyInfo = signature.getKeyInfo();
		List<X509Data> x509Datas = keyInfo.getX509Datas();
		X509Data x509Data = x509Datas.get(0);
		return x509Data.getX509Certificates().get(0);
	}

	/**
	 * This will zip, base64 encode, then url encode the message.
	 * 
	 * @param messageStr
	 * @return
	 * @throws MessageEncodingException
	 */
	private static String samlEncode(String messageStr) throws MessageEncodingException {
		try {
			ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
			Deflater deflater = new Deflater(Deflater.DEFLATED, true);
			DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
			deflaterStream.write(messageStr.getBytes());
			deflaterStream.finish();

			return URLEncoder.encode(
					org.opensaml.xml.util.Base64.encodeBytes(bytesOut.toByteArray(), org.opensaml.xml.util.Base64.DONT_BREAK_LINES),
					"UTF-8");
		} catch (IOException e) {
			throw new MessageEncodingException("Unable to DEFLATE and Base64 encode SAML message", e);
		}
	}
	
	/**
	 * Pulls the first signing certificate found in the SAML IDP metadata string
	 * 
	 * @param rawMetadataXml
	 * @return
	 * @throws ConfigurationException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 * @throws UnmarshallingException
	 * @throws CertificateException
	 * @throws DOMException
	 */
	protected static X509Certificate getIdpSsoSigningCertificatedFromMetadata(String rawMetadataXml) throws ConfigurationException, 
		ParserConfigurationException, SAXException, IOException, UnmarshallingException, CertificateException, DOMException {
		XMLObject metadata = unmarshall(rawMetadataXml);
		
		//finds the first signing certificate
		for(XMLObject c : metadata.getOrderedChildren()) {
			if(c != null && c.getElementQName().getLocalPart().equalsIgnoreCase("IDPSSODescriptor")) {
				IDPSSODescriptorImpl idsDesc = (IDPSSODescriptorImpl) c;
				for(KeyDescriptor kd : idsDesc.getKeyDescriptors()) {
					if(kd.getDOM().hasAttribute("use") && "signing".equals(kd.getDOM().getAttribute("use"))){
						return (X509Certificate) KeyInfoHelper
								.getCertificates(kd.getKeyInfo()).get(0);
					}
				}
			}
		}
		
		return null;
	}

	/**
	 * Constructs a SAML XMLObject from a raw string
	 * 
	 * @param xmlString
	 * @return
	 * @throws ConfigurationException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 * @throws UnmarshallingException
	 */
	private static XMLObject unmarshall(String xmlString) throws ConfigurationException, ParserConfigurationException, 
		SAXException, IOException, UnmarshallingException { 

		DefaultBootstrap.bootstrap();
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance(); 
		documentBuilderFactory.setNamespaceAware(true); 

		documentBuilderFactory.setExpandEntityReferences(false); 
		documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); 

		DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder(); 
		Document document = docBuilder.parse(new ByteArrayInputStream(xmlString.trim().getBytes(Charset.forName 
				("UTF-8")))); 
		Element element = document.getDocumentElement(); 
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory(); 
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element); 
		return unmarshaller.unmarshall(element); 
	} 
}
