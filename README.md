# Keycloak BCrypt

Add a password hash provider to handle BCrypt passwords inside Keycloak.

## Build
```
mvn clean package
```

## Install
```
curl http://repo.spring.io/release/org/springframework/security/spring-security-crypto/5.0.7.RELEASE/spring-security-crypto-5.0.7.RELEASE.jar > spring-security-crypto-5.0.7.jar
curl http://central.maven.org/maven2/commons-logging/commons-logging/1.1.1/commons-logging-1.1.1.jar


KEYCLOAK_HOME/bin/jboss-cli.sh \
    --command="module add \
        --name=org.springframework.security.crypto \
        --resources="spring-security-crypto-5.0.7.jar"
cp target/*.jar KEYCLOAK_HOME/standalone/deployments

KEYCLOAK_HOME/bin/jboss-cli.sh \
    --command="module add \
        --name=org.apache.commons.logging \
        --resources="commons-logging-1.1.1.jar"
cp target/*.jar KEYCLOAK_HOME/standalone/deployments
```

You need to restart Keycloak.