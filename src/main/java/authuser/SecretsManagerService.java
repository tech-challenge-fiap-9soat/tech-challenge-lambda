package authuser;

import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.util.Map;

public class SecretsManagerService {

    private final SecretsManagerClient secretsManagerClient;

    public SecretsManagerService() {
        this.secretsManagerClient = SecretsManagerClient.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    public Map<String, Object> getSecretCredentials(String secretName) {
        GetSecretValueRequest request = GetSecretValueRequest.builder()
                .secretId(secretName)
                .build();

        GetSecretValueResponse response = secretsManagerClient.getSecretValue(request);

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(response.secretString(), Map.class);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao obter credenciais do Secrets Manager", e);
        }
    }
}


