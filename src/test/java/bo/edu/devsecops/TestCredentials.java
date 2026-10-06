package bo.edu.devsecops;

/**
 * Credenciales SOLO para pruebas. El hash bcrypt correspondiente a
 * {@link #ADMIN_PASSWORD} vive en {@code src/test/resources/application-test.properties}.
 * Nunca reutilizar este valor fuera de las pruebas.
 */
public final class TestCredentials {

    public static final String ADMIN_USERNAME = "admin";
    public static final String ADMIN_PASSWORD = "Test-Admin-Pass-123!";

    private TestCredentials() {
    }
}
