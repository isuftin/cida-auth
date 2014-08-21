/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package gov.usgs.cida.auth.model;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
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
		
		String expResult = "{\"tokenId\":\"TEST-TOKEN-ID\",\"username\":\"isuftin@usgs.gov\",\"issued\":\"Aug 20, 2014 9:04:35 AM\",\"expires\":\"Aug 21, 2014 9:04:35 AM\",\"lastAccess\":\"Aug 20, 2014 9:04:35 AM\"}";
		String result = token.toJSON();
		assertEquals(expResult, result);
	}

	@Test
	public void testFromJSON() {
		System.out.println("fromJSON");
		String json = "{\"tokenId\":\"TEST-TOKEN-ID\",\"username\":\"isuftin@usgs.gov\",\"issued\":\"Aug 20, 2014 9:04:35 AM\",\"expires\":\"Aug 21, 2014 9:04:35 AM\",\"lastAccess\":\"Aug 20, 2014 9:04:35 AM\"}";
		AuthToken result = AuthToken.fromJSON(json);
		assertEquals("TEST-TOKEN-ID", result.getTokenId());
		assertEquals("isuftin@usgs.gov", result.getUsername());
		assertEquals(new Timestamp(1408543475000l), result.getIssued());
	}
	
}
