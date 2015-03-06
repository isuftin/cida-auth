package gov.usgs.cida.auth.exception;

/**
 *
 * @author thongsav
 */
public class ExpiredTokenException extends RuntimeException {

	/**
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Message constructor, expect to take the requested and invalid view as a
	 * message.
	 *
	 * @param message
	 */
	public ExpiredTokenException(String message) {
		super(message);
	}

	/**
	 * Message constructor, expect to take the requested and invalid view as a
	 * message.
	 *
	 * @param message The message to include
	 * @param t The causing exception or error
	 */
	public ExpiredTokenException(String message, Throwable t) {
		super(message, t);
	}
}
