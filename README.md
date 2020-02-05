# Keycloak BCrypt

Add a password hash provider to handle BCrypt passwords inside Keycloak.

## Build
```
mvn clean package
```

## Install
```
curl http://central.maven.org/maven2/org/mindrot/jbcrypt/0.4/jbcrypt-0.4.jar > jbcrypt-0.4.jar
KEYCLOAK_HOME/bin/jboss-cli.sh \
    --command="module add \
        --name=org.mindrot.jbcrypt \
        --resources="jbcrypt-0.4.jar"
cp target/*.jar KEYCLOAK_HOME/standalone/deployments
```
You need to restart Keycloak.

Docker is a bit different
