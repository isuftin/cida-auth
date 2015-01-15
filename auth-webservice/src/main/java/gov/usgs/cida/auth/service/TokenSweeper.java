package gov.usgs.cida.auth.service;

import gov.usgs.cida.auth.dao.AuthTokenDAO;
import java.util.Timer;
import java.util.TimerTask;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates a running thread that will remove expired tokens on a timed bases
 *
 * @author isuftin
 */
public class TokenSweeper implements ServletContextListener {
	private static final Logger LOG = LoggerFactory.getLogger(TokenSweeper.class);

	private Timer timer;
	private final long ONE_DAY = 86_400_000;
	
	@Override
	public void contextInitialized(ServletContextEvent sce) {
		timer = new Timer();
		LOG.info("Starting token sweeper");
		timer.schedule(new TokenSweeperTask(), 500, ONE_DAY);
		LOG.info("Started token sweeper");
	}

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
		LOG.info("Sending cancel reuqest to token sweeper");
		timer.cancel();
	}

	private static class TokenSweeperTask extends TimerTask {

		@Override
		public void run() {
			int deleted = new AuthTokenDAO().deleteExpiredTokens();
			LOG.info("Deleted {} expired tokens", deleted);
		}
		
	}
	
}
