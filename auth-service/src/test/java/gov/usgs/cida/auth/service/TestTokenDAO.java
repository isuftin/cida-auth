package gov.usgs.cida.auth.service;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import gov.usgs.cida.auth.dao.IAuthTokenDAO;
import gov.usgs.cida.auth.model.AuthToken;
import gov.usgs.cida.auth.model.User;

public class TestTokenDAO implements IAuthTokenDAO {
	List<AuthToken> authTokens = new ArrayList<>();
	{
		Calendar cal = Calendar.getInstance();
		Date nowDate = new Date();
		cal.setTime(nowDate);
				
		long now = nowDate.getTime();
		cal.add(Calendar.DATE, -2);
		long twoDaysAgo = cal.getTimeInMillis();
		
		cal.add(Calendar.DATE, 1);
		long yesterday = cal.getTimeInMillis();
		
		cal.add(Calendar.DATE, 2);
		long tomorrow = cal.getTimeInMillis();

		AuthToken expiredToken = new AuthToken();
		AuthToken validToken = new AuthToken();
		
		expiredToken.setTokenId("expiredTokenId");
		expiredToken.setId(new BigInteger("1"));
		expiredToken.setIssued(new Timestamp(twoDaysAgo));
		expiredToken.setLastAccess(new Timestamp(twoDaysAgo));
		expiredToken.setExpires(new Timestamp(yesterday));
		expiredToken.setRoles(Arrays.asList(new String[] { "ROLE1" }));

		validToken.setTokenId("validTokenId");
		validToken.setId(new BigInteger("2"));
		validToken.setIssued(new Timestamp(now));
		validToken.setLastAccess(new Timestamp(now));
		validToken.setExpires(new Timestamp(tomorrow));
		validToken.setRoles(Arrays.asList(new String[] { "ROLE2" }));
		
		authTokens.add(expiredToken);
		authTokens.add(validToken);
	}

	@Override
	public List<AuthToken> getAll() {
		return authTokens;
	}

	@Override
	public AuthToken getByTokenById(String id) {
		for(AuthToken t : authTokens) {
			if(t.getTokenId().equals(id)) {
				return t;
			}
		}
		return null;
	}

	@Override
	public List<String> getRoles(String username) {
		return Arrays.asList(new String[] { username });
	}

	@Override
	public List<AuthToken> getExpiredTokens() {
		//warning! this might not be the only expired token if the tokens are acted upon
		return Arrays.asList(new AuthToken[] { authTokens.get(0) });
	}

	@Override
	public int deleteTokenUsingId(String id) {
		if(id.equals("deletableToken")) {
			return 1;
		} else {
			return 0;
		}
	}

	@Override
	public int deleteExpiredTokens() {
		// will need to update this later
		return 1;
	}

	@Override
	public int insertToken(AuthToken token) {
		return 1;
	}

	@Override
	public int updateToken(AuthToken token) {
		for(AuthToken t: authTokens) {
			if(t.getTokenId().endsWith(token.getTokenId())) {
				t = token;
				return 1;
			}
		}
		
		return 0;
	}

	@Override
	public int updateTokenExpiration(AuthToken token) {
		return 1;
	}

	@Override
	public int updateTokenLastAccess(AuthToken token) {
		return 1;
	}

	@Override
	public AuthToken create(User user) {
		Calendar cal = Calendar.getInstance();
		Date nowDate = new Date();
		cal.setTime(nowDate);
				
		long now = nowDate.getTime();
		cal.add(Calendar.DATE, 1);
		long tomorrow = cal.getTimeInMillis();

		AuthToken t1 = new AuthToken();
		
		t1.setUsername(user.getUsername());
		t1.setTokenId("t2");
		t1.setId(new BigInteger("2"));
		t1.setIssued(new Timestamp(now));
		t1.setLastAccess(new Timestamp(now));
		t1.setExpires(new Timestamp(tomorrow));
		
		return t1;
	}

	@Override
	public AuthToken create(User user, int ttl) {
		Calendar cal = Calendar.getInstance();
		Date nowDate = new Date();
		cal.setTime(nowDate);
				
		long now = nowDate.getTime();
		cal.add(Calendar.SECOND, ttl);
		long tomorrow = cal.getTimeInMillis();

		AuthToken t1 = new AuthToken();
		
		t1.setUsername(user.getUsername());
		t1.setTokenId("t2");
		t1.setId(new BigInteger("2"));
		t1.setIssued(new Timestamp(now));
		t1.setLastAccess(new Timestamp(now));
		t1.setExpires(new Timestamp(tomorrow));
		
		return t1;
	}

	@Override
	public boolean exists(String tokenId) {
		for(AuthToken t : authTokens){
			if(t.getTokenId().equals(tokenId)) {
				return true;
			}
		}
		return false;
	}

}
