import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import java.io.StringWriter;
import java.security.Key;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import java.sql.*;

public class JWKSServer {

    private static RsaJsonWebKey jwk = null;
    private static RsaJsonWebKey expiredJWK = null;

    public static void main(String[] args) throws Exception {

        
	    //initialization of DB
        String url = "jdbc:sqlite:totally_not_my_privateKeys.db";
        Class.forName("org.sqlite.JDBC");
        Connection conn = DriverManager.getConnection(url);
        Statement stmt = conn.createStatement(); 
        stmt.execute("CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)");        

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


        //insert jwk into database.
        String sql = "INSERT INTO keys (key, exp) VALUES (?, ?)";
        try (Connection conn1 = DriverManager.getConnection(url);

            PreparedStatement pstmt = conn1.prepareStatement(sql)) {
            pstmt.setString(1, pemKey);
            pstmt.setString(2, String.valueOf(dateValue));
            pstmt.executeUpdate();
            System.out.println("RSA key stored successfully");
            
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        //converting jwk values and times into insertable values.
        String pemKey2 = KeyUtils.convertKeyToPEM(expiredJWK.getPrivateKey(), "RSA PRIVATE KEY");
        NumericDate date1 = NumericDate.now();
        Long dateValue1 = date1.getValue();

        //insert expiredJWK into database.
        try (Connection conn1 = DriverManager.getConnection(url);

            PreparedStatement pstmt = conn1.prepareStatement(sql)) {
            pstmt.setString(1, pemKey2);
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
        server.setExecutor(null); // creates a default executor
        server.start();
    }

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



            t.sendResponseHeaders(200, jwt.length());
            OutputStream os = t.getResponseBody();
            os.write(jwt.getBytes());
            os.close();



        }
    }
}
