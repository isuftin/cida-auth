/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package gov.usgs.cida.auth.model;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;

import org.junit.Test;

/**
 *
 * @author isuftin
 */
public class AuthTokenTest {
	
	public AuthTokenTest() {
	}
	
	@Test
	public void testToJSON() {
		System.out.println("toJSON");
		Calendar cal = Calendar.getInstance();
		long now = 1408543475000l;
		
		cal.setTime(new Date(now));
		cal.add(Calendar.DATE, 1);
		long tomorrow = cal.getTimeInMillis();
		
		AuthToken token = new AuthToken();
		String tokenId = "TEST-TOKEN-ID";
		String username = "isuftin@usgs.gov";
		
		token.setTokenId(tokenId);
		token.setUsername(username);
		token.setIssued(new Timestamp(now));
		token.setExpires(new Timestamp(tomorrow));
		token.setLastAccess(new Timestamp(now));
		
		String expResult = "{\"tokenId\":\"TEST-TOKEN-ID\",\"username\":\"isuftin@usgs.gov\",\"issued\":\"2014-08-20 09:04:35.0\",\"expires\":\"2014-08-21 09:04:35.0\",\"lastAccess\":\"2014-08-20 09:04:35.0\"}";
		String result = token.toJSON();
		assertEquals(expResult, result);
	}

	@Test
	public void testFromJSON() {
		System.out.println("fromJSON");
		String json = "{\"tokenId\":\"TEST-TOKEN-ID\",\"username\":\"isuftin@usgs.gov\",\"issued\":\"2014-08-20 09:04:35.0\",\"expires\":\"2014-08-21 09:04:35.0\",\"lastAccess\":\"2014-08-20 09:04:35.0\"}";
		AuthToken result = AuthToken.fromJSON(json);
		assertEquals("TEST-TOKEN-ID", result.getTokenId());
		assertEquals("isuftin@usgs.gov", result.getUsername());
		assertEquals(new Timestamp(1408543475000l), result.getIssued());
	}
	
	@Test
	public void testExtendExpiration() {
		System.out.println("testExtendExpiration");
		AuthToken token = new AuthToken();
		String tokenId = "TEST-TOKEN-ID";
		Calendar cal = Calendar.getInstance();
		Date dt = new Date();
		long now = dt.getTime();

		cal.setTime(dt);
		cal.add(Calendar.HOUR, 1);
		long extendedExpiration = cal.getTimeInMillis();

		token.setTokenId(tokenId);
		token.setIssued(new Timestamp(now));
		token.setExpires(new Timestamp(now));
		token.setLastAccess(new Timestamp(now));

		// Extend it one hour
		token.extendExpiration(3600);
		Timestamp expires = token.getExpires();
		assertThat(expires.getTime(), is(equalTo(extendedExpiration)));
		
		// Extend it another day
		token.setLastAccess(new Timestamp(extendedExpiration));
		token.extendExpiration(3600);
		expires = token.getExpires();
		assertThat(expires.getTime(), is(greaterThan(extendedExpiration)));
	}
	
	@Test
	public void testIsExpired() {
		System.out.println("testIsExpired");
		AuthToken token = new AuthToken();
		Date dt = new Date();
		Calendar cal = Calendar.getInstance();
		cal.setTime(dt);
		cal.add(Calendar.DATE, -1);
		long yesterday = cal.getTimeInMillis();
		
		cal.add(Calendar.DATE, +2);
		long tomorrow = cal.getTimeInMillis();
		
		token.setExpires(new Timestamp(yesterday));
		boolean expired = token.isExpired();
		assertThat(expired, is(Boolean.TRUE));
		
		token.setExpires(new Timestamp(tomorrow));
		expired = token.isExpired();
		assertThat(expired, is(Boolean.FALSE));
	}	
}
