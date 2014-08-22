package gov.usgs.cida.auth.model;

import com.google.gson.Gson;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.Calendar;

/**
 * Represents an authentication token issued to calling clients
 * @author isuftin
 */
public class AuthToken {
	private BigInteger id;
	private String tokenId;
	private String username;
	private Timestamp issued;
	private Timestamp expires;
	private Timestamp lastAccess;

	/**
	 * Serializes AuthToken to JSON 	 * 
	 * @return 
	 */
	public String toJSON() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }
	
	/**
	 * Deserializes JSON to AuthToken
	 * @param json
	 * @return 
	 */
	public static AuthToken fromJSON(String json) {
		Gson gson = new Gson();
		return gson.fromJson(json, AuthToken.class);
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

	public void extendExpiration(int seconds) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(this.expires);
		cal.add(Calendar.SECOND, seconds);
		this.expires = new Timestamp(cal.getTimeInMillis());
	}
}
