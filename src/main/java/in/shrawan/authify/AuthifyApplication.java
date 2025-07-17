package in.shrawan.authify;


import org.springframework.beans.factory.annotation.Value; // <--- ADD THIS IMPORT
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent; // <--- ADD THIS IMPORT
import org.springframework.context.event.EventListener; // <--- ADD THIS IMPORT
import org.slf4j.Logger; // <--- ADD THIS IMPORT
import org.slf4j.LoggerFactory; // <--- ADD THIS IMPORT


@SpringBootApplication
public class AuthifyApplication {

	private static final Logger log = LoggerFactory.getLogger(AuthifyApplication.class); // <--- ADD THIS

	// --- ADD THESE LINES FOR DEBUGGING ---
	@Value("${DB_URL}")
	private String dbUrlValue;

	@Value("${DB_USERNAME}")
	private String dbUsernameValue;

	@EventListener(ApplicationReadyEvent.class)
	public void doSomethingAfterStartup() {
		log.info("DEBUG_ENV: DB_URL value is: {}", dbUrlValue); // This should print the value
		log.info("DEBUG_ENV: DB_USERNAME value is: {}", dbUsernameValue); // This should print the value
		log.info("DEBUG_ENV: Full JDBC URL (from System Property): {}", System.getProperty("DB_URL"));
		log.info("DEBUG_ENV: Full JDBC URL (from OS Env): {}", System.getenv("DB_URL"));

		if (dbUrlValue == null || dbUrlValue.isEmpty()) {
			log.error("DEBUG_ENV: DB_URL is NULL or EMPTY after injection!");
		}
	}
	// --- END DEBUGGING ADDITIONS ---


	public static void main(String[] args) {


		SpringApplication.run(AuthifyApplication.class, args);
	}

}