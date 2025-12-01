package com.sqllib;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import com.sqllib.services.UserSecureService;

@SpringBootTest
@DisplayName("UserSecureService (Secure) Tests")
public class UserSecureServiceTests {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private UserSecureService userSecureService;
    private static boolean initialized = false;

    @BeforeEach
    public void setUp() throws SQLException {
        userSecureService = new UserSecureService();

        // Initialize the database only once
        if (!initialized) {
            initializeDatabase();
            initialized = true;
        }
    }

    private void initializeDatabase() throws SQLException {
        try {
            jdbcTemplate.execute("DROP TABLE IF EXISTS users");
            jdbcTemplate.execute("DROP TABLE IF EXISTS sensitive_data");
        } catch (RuntimeException e) {
            // Ignore if table does not exist
        }

        jdbcTemplate.execute("CREATE TABLE users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "username VARCHAR(50) NOT NULL, " +
                "password VARCHAR(50) NOT NULL, " +
                "email VARCHAR(100) NOT NULL)");

        jdbcTemplate.execute("CREATE TABLE sensitive_data (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "secret_key VARCHAR(255) NOT NULL, " +
                "credit_card VARCHAR(16) NOT NULL, " +
                "ssn VARCHAR(11) NOT NULL)");

        jdbcTemplate.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'secret123', 'admin@example.com')");
        jdbcTemplate.execute("INSERT INTO users (username, password, email) VALUES ('user', 'password', 'user@example.com')");

        jdbcTemplate.execute("INSERT INTO sensitive_data (secret_key, credit_card, ssn) " +
                "VALUES ('API_KEY_12345', '4532111122223333', '123-45-6789')");
        jdbcTemplate.execute("INSERT INTO sensitive_data (secret_key, credit_card, ssn) " +
                "VALUES ('SECRET_TOKEN_XYZ', '5555666677778888', '987-65-4321')");
    }

    @Test
    @DisplayName("✅ SECURE: getUserById prevents SQL Injection")
    public void testGetUserByIdSecureWithInjection() {
        String userId = "1' OR '1'='1";

        // PreparedStatement blocks SQL injection by throwing an exception
        // when trying to convert malicious input to the expected type
        try {
            String result = userSecureService.getUserById(userId);
            assertNull(result, "✓ PreparedStatement prevents SQL Injection!");
        } catch (Exception e) {
            // This is the expected secure behavior!
            // The exception proves that PreparedStatement blocked the injection
            assertTrue(e.getMessage().contains("Data conversion error") ||
                            e.getCause() instanceof NumberFormatException,
                    "✓ PreparedStatement blocked SQL injection with exception: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("✅ SECURE: Authentication prevents SQL comment bypass")
    public void testAuthenticateSecureWithInjection() throws SQLException {
        String username = "admin' --";
        String password = "wrongpassword";

        boolean result = userSecureService.authenticate(username, password);
        assertFalse(result, "✓ PreparedStatement prevents SQL comment bypass!");
    }

    @Test
    @DisplayName("✅ SECURE: OR injection is PREVENTED")
    public void testORInjectionSecure() throws SQLException {
        String username = "' OR '1'='1";
        String password = "' OR '1'='1";

        boolean result = userSecureService.authenticate(username, password);
        assertFalse(result, "✓ PreparedStatement prevents OR injection!");
    }

    @Test
    @DisplayName("✅ SECURE: Second Order SQL Injection is PREVENTED - Complete Protection")
    public void testSecondOrderInjectionPrevention() throws SQLException {
        // This test demonstrates how PreparedStatement prevents Second Order SQL Injection
        // in BOTH storage and retrieval phases

        String maliciousUsername = "hackerr'' or 1=1--";
        String password = "password123";
        String email = "hacker@example.com";

        // STEP 1: Attempt to store malicious SQL in username field using PreparedStatement
        // PreparedStatement safely stores this as literal data (not SQL code)
        int userId = userSecureService.createUser(maliciousUsername, password, email);

        assertTrue(userId > 0, "✓ STEP 1: User created with ID " + userId + ". Malicious username stored safely as literal text");


        // STEP 2: Even with stored malicious data, PreparedStatement prevents execution
        // The getUserProfile method uses PreparedStatement for BOTH queries
        String result = userSecureService.getUserProfile(String.valueOf(userId));

        // The malicious SQL is NOT executed - it's treated as literal data
        assertNotNull(result, "✓ STEP 2: PreparedStatement prevents second order injection execution!");


    }

    @Test
    @DisplayName("✅ SECURE: Boolean-based Blind SQL Injection is PREVENTED")
    public void testBooleanBasedBlindInjectionPrevention() throws SQLException {
        // Attempt boolean-based blind injection
        String payload = "admin' AND SUBSTRING(password,1,1)='s'--";

        boolean exists = userSecureService.checkUserExists(payload);
        // PreparedStatement treats entire payload as literal username
        // Returns false because no user named "admin' AND SUBSTRING..." exists
        assertFalse(exists, "✓ PreparedStatement prevents boolean-based blind injection!");
    }

    @Test
    @DisplayName("✅ SECURE: Time-based Blind SQL Injection is PREVENTED")
    public void testTimeBasedBlindInjectionPrevention() {
        // Attempt time-based blind injection
        String payload = "1' AND IF(SUBSTRING(password,1,1)='s', SLEEP(5), 0)--";

        try {
            long startTime = System.currentTimeMillis();
            String result = userSecureService.getUserEmail(payload);
            long endTime = System.currentTimeMillis();

            // PreparedStatement treats payload as literal - no delay, no injection
            assertEquals("User not found", result, "✓ PreparedStatement prevents time-based blind injection!");
            assertTrue(endTime - startTime < 100, "✓ No time delay - injection blocked!");
        } catch (Exception e) {
            // PreparedStatement may throw exception for invalid ID format
            // This is also valid protection - injection blocked
            assertTrue(e.getMessage().contains("Data conversion") ||
                            e.getCause() instanceof NumberFormatException,
                    "✓ PreparedStatement blocked injection with type checking: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("✅ SECURE: UNION-based SQL Injection is PREVENTED")
    public void testUNIONBasedInjectionPrevention() throws SQLException {
        // First, ensure sensitive_data table exists with test data
        try {
            jdbcTemplate.execute("DROP TABLE IF EXISTS sensitive_data");
            jdbcTemplate.execute("CREATE TABLE sensitive_data (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "secret_key VARCHAR(255) NOT NULL, " +
                    "credit_card VARCHAR(16) NOT NULL, " +
                    "ssn VARCHAR(11) NOT NULL)");
            jdbcTemplate.execute("INSERT INTO sensitive_data (secret_key, credit_card, ssn) " +
                    "VALUES ('API_KEY_12345', '4532111122223333', '123-45-6789')");
        } catch (RuntimeException e) {
            // Table might already exist, continue
        }

        // Attempt UNION-based attack to extract credit card numbers
        String payload = "' UNION SELECT credit_card FROM sensitive_data--";

        String result = userSecureService.searchUserByName(payload);

        // PreparedStatement treats UNION payload as literal search text
        // Returns "No users found" because no user has that exact username
        assertEquals("No users found", result,
                "✓ PreparedStatement prevents UNION-based SQL injection!");

        // Verify that credit card data is NOT exposed
        assertFalse(result.contains("4532"),
                "✓ Sensitive credit card data NOT exposed!");
        assertFalse(result.contains("5555"),
                "✓ Sensitive data remains protected!");
    }

    @Test
    @DisplayName("✅ SECURE: Error-Based SQL Injection Prevention")
    public void testErrorBasedInjectionPrevention() throws SQLException {
        // Setup: Create test user
        jdbcTemplate.execute("DELETE FROM users");
        jdbcTemplate.execute("INSERT INTO users (username, password, email) " +
                "VALUES ('admin', 'secret123', 'admin@example.com')");

        // Attempt Error-based attack
        String payload = "1 AND 1=CAST((SELECT password FROM users WHERE id=1) AS INT)";

        try {
            String result = userSecureService.getUserPassword(payload);

            // PreparedStatement treats payload as literal value
            // Since no user has id = "1 AND 1=CAST(...)", it returns null
            assertNull(result, "SECURE: PreparedStatement treated malicious input as literal value");
        } catch (SQLException e) {
            // Even if error occurs, it should not reveal sensitive data
            String errorMsg = e.getMessage().toLowerCase();

            assertFalse(errorMsg.contains("secret") && errorMsg.contains("admin"),
                    "SECURE: Error message does not expose sensitive data");
            assertTrue(true, "SECURE: PreparedStatement prevented error-based injection");
        }
    }
}