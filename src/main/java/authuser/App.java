package authuser;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.sql.Connection;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Handler for requests to Lambda function.
 */
public class App implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        System.out.println("...RUNNING LAMBDA AUTH-USER...");

        String dbSecret = System.getenv("DB_SECRET");
        String cognitoSecret = System.getenv("COGNITO_SECRET");

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("X-Custom-Header", "application/json");

        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);
        SecretsManagerService secretsManagerService = new SecretsManagerService();

        try {
            String requestBody = input.getBody();

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(requestBody);

            String cpf = jsonNode.get("cpf").asText();

            if (this.userExists(cpf, secretsManagerService.getSecretCredentials(dbSecret))) {
                String tokenJWT = this.generateTokenJWT(secretsManagerService.getSecretCredentials(cognitoSecret));
                return response
                        .withStatusCode(200)
                        .withBody(tokenJWT);
            }

        } catch (Exception e) {
            System.out.println("AN ERROR OCCURRED =(");
            e.printStackTrace();
        }

        return response
                .withBody("User Not Found")
                .withStatusCode(404);
    }

    private boolean userExists(String cpf, Map<String, Object> credentials) {
        String username = credentials.get("username").toString();
        String password = credentials.get("password").toString();

        String url = String.format("jdbc:postgresql://%s:%s/%s",
                credentials.get("host"),
                credentials.get("port"),
                credentials.get("dbname")
        );

        System.out.println("===DB CONNECTING===");
        try (Connection connection = DriverManager.getConnection(url, username, password)) {
            System.out.println("===SEARCHING CPF===");
            String sql = "SELECT * FROM cliente WHERE cpf = ?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, cpf);
                ResultSet resultSet = statement.executeQuery();

                if (resultSet.next()) {
                    System.out.println("===CPF FOUNDED!===");
                    return true;
                }
            }
        } catch (SQLException e) {
            System.out.println("ERROR WHEN SEARCHING FOR CPF =(");
            e.printStackTrace();
        }
        return false;
    }

    private String generateTokenJWT(Map<String, Object> credentials) {
        String tokenJWT = null;
        try {
            System.out.println("===JWT GENERATING===");
            OkHttpClient client = new OkHttpClient.Builder().build();

            RequestBody formBody = new FormBody.Builder()
                    .add("client_id", credentials.get("clientId").toString())
                    .add("client_secret", credentials.get("clientSecret").toString())
                    .add("scope", "default-m2m-resource-server-tcb5yq/read")
                    .add("grant_type", "client_credentials")
                    .build();

            Request request = new Request.Builder()
                    .url(credentials.get("url").toString())
                    .post(formBody)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .build();

            Response cognitoResponse = client.newCall(request).execute();

            if (cognitoResponse.body() != null) {
                tokenJWT = cognitoResponse.body().string();
            }
        } catch (Exception e) {
            System.out.println("ERROR WHEN GENERATING TOKEN JWT =(");
            e.printStackTrace();
        }

        return tokenJWT;
    }
}