package gov.usgs.cida.auth.dao;

import java.util.List;

public interface IFederatedAuthDAO {

	/**
	 * Retrieves a list of domains a user can be in, eg: usgs.gov
	 *
	 * @param username
	 * @return
	 */
	public List<String> getAllAcceptedDomains();

	/**
	 * Gets a list of all accepted forward URLs we will allow user forwarding to
	 *
	 * @return
	 */
	public List<String> getAllAcceptedForwardUrls();

}