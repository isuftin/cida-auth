package gov.usgs.cida.auth.model;

import java.sql.Timestamp;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import org.slf4j.LoggerFactory;

/**
 *
 * @author isuftin
 */
public class TimestampAdapter extends XmlAdapter<String, Timestamp> {
	private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(TimestampAdapter.class);
	
	@Override
	public String marshal(Timestamp v) {
		return v.toString();
	}

	@Override
	public Timestamp unmarshal(String v) {
		 Timestamp timestamp = null;
		 try {
			 timestamp = Timestamp.valueOf(v);
		 } catch (IllegalArgumentException ex) {
			 LOG.warn("Could not parse incoming timestamp", ex);
		 }
		return timestamp;
	}
}
