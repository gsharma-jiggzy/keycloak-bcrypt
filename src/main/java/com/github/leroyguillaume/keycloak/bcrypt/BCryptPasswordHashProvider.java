package com.github.leroyguillaume.keycloak.bcrypt;

import org.jboss.logging.Logger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserCredentialModel;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.regex.Pattern;


import java.io.IOException;

/**
 * @author <a href="mailto:pro.guillaume.leroy@gmail.com">Guillaume Leroy</a>
 */
public class BCryptPasswordHashProvider implements PasswordHashProvider {
    private final int defaultIterations;
    private final String providerId;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    private Pattern BCRYPT_PATTERN = Pattern
            .compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");

    public BCryptPasswordHashProvider(String providerId, int defaultIterations) {
        this.providerId = providerId;
        this.defaultIterations = defaultIterations;
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder(defaultIterations);
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, CredentialModel credential) {
        int policyHashIterations = policy.getHashIterations();
        if (policyHashIterations == -1) {
            policyHashIterations = defaultIterations;
        }

        return credential.getHashIterations() == policyHashIterations && providerId.equals(credential.getAlgorithm());
    }

    @Override
    public String encode(String rawPassword, int iterations) {
        if (isHashed(rawPassword)) {
            return rawPassword;
        }
        else {
            bCryptPasswordEncoder = new BCryptPasswordEncoder(iterations);
            return bCryptPasswordEncoder.encode(rawPassword);
        }
    }

    @Override
    public void encode(String rawPassword, int iterations, CredentialModel credential) {
        if (iterations == -1) {
            iterations = defaultIterations;
        }
        bCryptPasswordEncoder = new BCryptPasswordEncoder(iterations);
        String salt = BCrypt.gensalt(iterations);
        String password;
        if (isHashed(rawPassword)) {
            password = rawPassword;
        }
        else {
            password = bCryptPasswordEncoder.encode(rawPassword);
        }

        credential.setAlgorithm(providerId);
        credential.setType(UserCredentialModel.PASSWORD);
        credential.setHashIterations(iterations);
        credential.setValue(password);
        try {
            // Encode String to base 64
            String saltEncode = Base64.getEncoder().encodeToString(salt.getBytes());
            byte[] saltDecode = Base64.getDecoder().decode(saltEncode);
            credential.setSalt(saltDecode);
            // credential.setSalt(Base64.getDecoder().decode(salt));
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    private boolean isHashed(String rawPassword) {
        return BCRYPT_PATTERN.matcher(rawPassword).matches();
    }

    @Override
    public void close() {
    }

    @Override
    public boolean verify(String rawPassword, CredentialModel credential) {
        return bCryptPasswordEncoder.matches(rawPassword, credential.getValue());
    }
}
