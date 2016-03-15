package gov.usgs.cida.auth.model;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.google.gson.GsonBuilder;

/**
 * Represents an authentication token issued to calling clients
 *
 * @author isuftin
 */
public class AuthToken {
	private final static String dateFormat = "yyyy-MM-dd HH:mm:ss.S";
	private BigInteger id;
	private String tokenId;
	private String username;
	@XmlJavaTypeAdapter(TimestampAdapter.class)
	private Timestamp issued;
	@XmlJavaTypeAdapter(TimestampAdapter.class)
	private Timestamp expires;
	@XmlJavaTypeAdapter(TimestampAdapter.class)
	private Timestamp lastAccess;
	private List<String> roles;
	
	private int ttl = 60000; //default 1 hour

	/**
	 * Serializes AuthToken to JSON
	 *
	 * @return
	 */
	public String toJSON() {
		return new GsonBuilder().setDateFormat(dateFormat).create().toJson(this);
	}

	/**
	 * Deserializes JSON to AuthToken
	 *
	 * @param json
	 * @return
	 */
	public static AuthToken fromJSON(String json) {
		return new GsonBuilder().setDateFormat(dateFormat).create().fromJson(json, AuthToken.class);
	}

	/**
	 * @return the id
	 */
	public BigInteger getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(BigInteger id) {
		this.id = id;
	}

	/**
	 * @return the tokenId
	 */
	public String getTokenId() {
		return tokenId;
	}

	/**
	 * @param tokenId the tokenId to set
	 */
	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	/**
	 * @return the username
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * @param username the username to set
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * @return the issued
	 */
	public Timestamp getIssued() {
		return issued;
	}

	/**
	 * @param issued the issued to set
	 */
	public void setIssued(Timestamp issued) {
		this.issued = issued;
	}

	/**
	 * @return the expires
	 */
	public Timestamp getExpires() {
		return expires;
	}

	/**
	 * @param expires the expires to set
	 */
	public void setExpires(Timestamp expires) {
		this.expires = expires;
	}

	/**
	 * @return the lastAccess
	 */
	public Timestamp getLastAccess() {
		return lastAccess;
	}

	/**
	 * @param lastAccess the lastAccess to set
	 */
	public void setLastAccess(Timestamp lastAccess) {
		this.lastAccess = lastAccess;
	}
	
	/**
	 * @return roles
	 */
	public List<String> getRoles() {
		return roles;
	}
	
	/**
	 * @param roles
	 */
	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

	/**
	 * Extends the expiration date for this token to a day after its last
	 * accessed date
	 */
	public void extendExpiration() {
		extendExpiration(ttl);
	}

	/**
	 * Extends the token expiration date
	 *
	 * @param seconds amount of seconds to extend the expiration date by
	 */
	public void extendExpiration(int seconds) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(this.expires);
		cal.add(Calendar.SECOND, seconds);
		this.expires = new Timestamp(cal.getTimeInMillis());
	}

	/**
	 * Sets the last access timestamp of the token to now
	 */
	public void updateLastAccess() {
		this.lastAccess = new Timestamp(new Date().getTime());
	}

	public boolean isExpired() {
		return this.expires.before(new Date());
	}
}
