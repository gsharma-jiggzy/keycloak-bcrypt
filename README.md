# Keycloak BCrypt

Add a password hash provider to handle BCrypt passwords inside Keycloak.

## Build
```
mvn clean package
```

## Install
```
curl http://repo.spring.io/release/org/springframework/security/spring-security-crypto/5.0.7.RELEASE/spring-security-crypto-5.0.7.RELEASE.jar > spring-security-crypto-5.0.7.jar


KEYCLOAK_HOME/bin/jboss-cli.sh \
    --command="module add \
        --name=org.springframework.security.crypto \
        --resources="spring-security-crypto-5.0.7.jar"
cp target/*.jar KEYCLOAK_HOME/standalone/deployments
```

You need to restart Keycloak.