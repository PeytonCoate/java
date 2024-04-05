import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import java.io.StringWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.sql.*;
import java.util.UUID;

public class JWKSServer {

    private static RsaJsonWebKey jwk = null;
    private static RsaJsonWebKey expiredJWK = null;
    private static final String url = "jdbc:sqlite:totally_not_my_privateKeys.db";
    public static void main(String[] args) throws Exception {
        
	    //initialization of DB

        Class.forName("org.sqlite.JDBC");
        Connection conn = DriverManager.getConnection(url);
        Statement stmt = conn.createStatement();

        //Create database tables.
        stmt.execute("CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)");        
        stmt.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
        stmt.execute("CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))");

        //Create private RSA key encryption.
        String envVar = System.getenv("NOT_MY_KEY");
        
        // Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
        jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId("goodKey1");
        expiredJWK = RsaJwkGenerator.generateJwk(2048);
        expiredJWK.setKeyId("expiredKey");


        //converting jwk values and times into insertable values.
        String pemKey = KeyUtils.convertKeyToPEM(jwk.getPrivateKey(), "RSA PRIVATE KEY");
        NumericDate date = NumericDate.now();
        date.addSeconds(60 * 60);
        Long dateValue = date.getValue();
        String encryptedPemKey = encryptPEM(pemKey, envVar); //encrypt PEM key

        String pemKey2 = KeyUtils.convertKeyToPEM(expiredJWK.getPrivateKey(), "RSA PRIVATE KEY"); //ExpiredJWK
        NumericDate date1 = NumericDate.now();
        Long dateValue1 = date1.getValue();
        String encryptedPemKey2 = encryptPEM(pemKey2, envVar); //encrypt PEM key


        //insert jwk into database.
        String sql = "INSERT INTO keys (key, exp) VALUES (?, ?)";
        try (Connection conn1 = DriverManager.getConnection(url);

            PreparedStatement pstmt = conn1.prepareStatement(sql)) {
            pstmt.setString(1, encryptedPemKey);
            pstmt.setString(2, String.valueOf(dateValue));
            pstmt.executeUpdate();
            System.out.println("RSA key stored successfully");
            
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        try (Connection conn1 = DriverManager.getConnection(url);

            PreparedStatement pstmt = conn1.prepareStatement(sql)) {
            pstmt.setString(1, encryptedPemKey2);
            pstmt.setString(2, String.valueOf(dateValue1));
            pstmt.executeUpdate();
            System.out.println("RSA key stored successfully");
            
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        //send authhandler, start server
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler());
        server.createContext("/auth", new AuthHandler());
        server.createContext("/register", new RegisterHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    /*PEM CONVERSION */
    static class KeyUtils {
        public static String convertKeyToPEM(Key key, String keyType) {
            StringWriter stringWriter = new StringWriter();
            try (PemWriter pemWriter = new PemWriter(stringWriter)) {
                PemObject pemObject = new PemObject(keyType, key.getEncoded());
                pemWriter.writeObject(pemObject);
            } catch (Exception e) {
                System.out.println("Error converting key to PEM format: " + e.getMessage());
                return null;
            }
            return stringWriter.toString();
        }
    }


    /*PEM ENCRYPTION */

    public static String encryptPEM(String pemKey, String password) throws Exception {
        // Generate AES key from password
        SecretKeySpec secretKeySpec = generateAESKey(password);

        // Initialize AES cipher in encryption mode
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // Encrypt PEM key
        byte[] encryptedPemKeyBytes = cipher.doFinal(pemKey.getBytes());

        // Convert encrypted bytes to Base64 String
        return new String(java.util.Base64.getEncoder().encode(encryptedPemKeyBytes));
    }    

    private static SecretKeySpec generateAESKey(String password) throws NoSuchAlgorithmException {
        // Convert password to bytes
        byte[] passwordBytes = password.getBytes();

        // Use SHA-256 hash of password as AES key
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(passwordBytes);

        // AES key should be 16, 24, or 32 bytes long
        byte[] aesKey = new byte[16]; // 128-bit key
        System.arraycopy(key, 0, aesKey, 0, 16);

        return new SecretKeySpec(aesKey, "AES");
    }


    /*HANDLERS */
    static class JWKSHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            if (!"GET".equalsIgnoreCase(t.getRequestMethod())) {
                t.sendResponseHeaders(405, -1); // 405 Method Not Allowed
                return;
            }
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwk);
            String jwks = jsonWebKeySet.toJson();
            t.getResponseHeaders().add("Content-Type", "application/json");
            t.sendResponseHeaders(200, jwks.length());
            OutputStream os = t.getResponseBody();
            os.write(jwks.getBytes());
            os.close();
        }
    }

    

    static class AuthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            
            if (!"POST".equalsIgnoreCase(t.getRequestMethod())) {
                t.sendResponseHeaders(405, -1); // 405 Method Not Allowed
                return;
            }
/* 
            String requestBody = Utils.convertStreamToString(t.getRequestBody());
            String[] parts = requestBody.split(":");
            String username = parts[1].split(",")[0].replaceAll("\"", "").trim();
            String userPassword = parts[2].replaceAll("\"", "").trim();

            try (Connection conn = DriverManager.getConnection(url, username, userPassword)) {
                String sql = "SELECT * FROM users WHERE user_id = ? AND password_hash = ?";
                
                try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                    pstmt.setString(1, user_id);
                    pstmt.setString(2, userPassword);
                    
                    try (ResultSet rs = pstmt.executeQuery()) {
                        if (rs.next()) {
                            // User authentication successful
                            // Do something
                        } else {
                            // User authentication failed
                            // Do something else
                        }
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
*/
            JwtClaims claims = new JwtClaims();
            claims.setGeneratedJwtId();
            claims.setIssuedAtToNow();
            claims.setSubject("sampleUser");
            claims.setExpirationTimeMinutesInTheFuture(60);

            JsonWebSignature jws = new JsonWebSignature();
            jws.setKeyIdHeaderValue(jwk.getKeyId());
            jws.setKey(jwk.getPrivateKey());

            // Check for the "expired" query parameter
            if (t.getRequestURI().getQuery() != null && t.getRequestURI().getQuery().contains("expired=true")) {
                NumericDate expirationTime = NumericDate.now();
                expirationTime.addSeconds(-60 * 60); // Subtract 60 minutes
                claims.setExpirationTime(expirationTime);
                jws.setKeyIdHeaderValue(expiredJWK.getKeyId());
                jws.setKey(expiredJWK.getPrivateKey());
            }

            jws.setPayload(claims.toJson());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

            String jwt = "";
            try {
                jwt = jws.getCompactSerialization();
            } catch (JoseException e) {
                e.printStackTrace();
                t.sendResponseHeaders(500, -1); // 500 Internal Server Error
                return;
            }
            String requestIp = t.getRemoteAddress().getAddress().getHostAddress();
            int userId = extractUserIdFromRequest(t);
            logAuthRequest(requestIp, userId);

            t.sendResponseHeaders(200, jwt.length());
            OutputStream os = t.getResponseBody();
            os.write(jwt.getBytes());
            os.close();
        }
    }
    //TODO: actually extract user ID via parsing.
    private static int extractUserIdFromRequest(HttpExchange exchange) {
        return 123; // Placeholder
    }

    // Method to log authentication requests
    public static void logAuthRequest(String requestIp, int userId) {
        String sql = "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            // Set parameters
            pstmt.setString(1, requestIp);
            pstmt.setInt(2, userId);

            // Execute the insert statement
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace(); // Proper error handling would be to log the error instead
        }
    }



    //Password handler.
    static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {

            if ("POST".equals(exchange.getRequestMethod())) {
                // Parse JSON request body
                String requestBody = Utils.convertStreamToString(exchange.getRequestBody());
                String[] parts = requestBody.split(":");
                String username = parts[1].split(",")[0].replaceAll("\"", "").trim();
                String email = parts[2].replaceAll("\"", "").trim();

                // Generate secure password using UUIDv4
                String password = UUID.randomUUID().toString();
                System.out.println(password);
                //Hash password using Argon2
                String hashedPassword = hashPassword(password);

                try {
                    insertUser(username, hashedPassword, email);
                } catch (SQLException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); //Internal Server Error
                    return;
                }

 
                //JSON response
                String response = "{\"password\": \"" + hashedPassword + "\"}";

                  //response headers
                exchange.getResponseHeaders().set("Content-Type", "application/json");

                // Status code
                int statusCode = hashedPassword != null ? 200 : 500;
                String statusMessage = hashedPassword != null ? "OK" : "Internal Server Error";
                exchange.sendResponseHeaders(statusCode, response.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } else {
                // Method not allowed
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
    private static String hashPassword(String password) {
        //Argon2 argon2 = Argon2Factory.create();
        //String hashedPassword = argon2.hash(10, 65536, 1, password);
        //return DigestUtils.sha256Hex(password); TODO: Fix argon2 hash.
        return password;
    }


    // convert InputStream to String
    static class Utils {
        static String convertStreamToString(java.io.InputStream is) {
            java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";

        }
    }


    // Insert user details into the database
    private static void insertUser(String username, String hashedPassword, String email) throws SQLException {
        try (Connection conn3 = DriverManager.getConnection(url)) {
            String query = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)";
            try (PreparedStatement pstmt = conn3.prepareStatement(query)) {
                pstmt.setString(1, username);
                pstmt.setString(2, hashedPassword);
                pstmt.setString(3, email);
                pstmt.executeUpdate();
                System.out.println("lole");
            }
        }
    }
}
