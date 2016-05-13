package gov.usgs.cida.auth.service.authentication;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import java.security.cert.X509Certificate;
import org.w3c.dom.DOMException;
import org.xml.sax.SAXException;

public class SamlServiceTest {

	@Test
	public void test_getIdpSsoSigningCertificatedFromMetadata() throws FileNotFoundException, IOException, URISyntaxException, CertificateException, DOMException, ConfigurationException, ParserConfigurationException, SAXException, UnmarshallingException {
		String rawMetadataXml = IOUtils.toString(new FileInputStream(new File(
				SamlServiceTest.class.getResource("/idp.ssocircle.com.xml").toURI())), Charset.defaultCharset());
		X509Certificate test = SamlService.getIdpSsoSigningCertificatedFromMetadata(rawMetadataXml);
		assertNotNull(test);
	}
}
