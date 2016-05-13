package gov.usgs.cida.auth.exception;

public class NotAuthorizedException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public NotAuthorizedException() {
		super();
	}

	public NotAuthorizedException(String m) {
		super(m);
	}
}
