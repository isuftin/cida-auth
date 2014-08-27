package gov.usgs.cida.auth.client;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author isuftin
 */
public class SSLTool {

	private static final Logger LOG = LoggerFactory.getLogger(SSLTool.class);

	public static Client getRelaxedSSLClient() {
		Client client;

		TrustManager[] trustAllCerts = new TrustManager[]{
			new X509TrustManager() {
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}

				@Override
				public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
					// Do nothing here
				}

				@Override
				public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
					// Do nothing here
				}
			}};

		HostnameVerifier hv = new HostnameVerifier() {
			@Override
			public boolean verify(String str, SSLSession sslSession) {
				return true;
			}
		};

		try {
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new SecureRandom());
			client = ClientBuilder.newBuilder().hostnameVerifier(hv).sslContext(sc).build();
		} catch (NoSuchAlgorithmException | KeyManagementException ex) {
			LOG.warn("Unable to creat relaxed SSL client.", ex);
			client = ClientBuilder.newClient();
		}

		return client;
	}
}
