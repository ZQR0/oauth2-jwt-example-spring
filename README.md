# Spring OAuth2 Project

## Project structure
```text
keycloak-auth-server
|
client-server
|
resource-server
```

Gradle multi-module enabled: [Gradle multi-module example]('https://github.com/ZQR0/gradle-multi-project-example-spring)

## About
* Keycloak server (port :8081) - provides auth functionality
* Client server (port :8082) - provides client side
* Resource server (port :8083) - provides all resources

## KeyCloak with Docker
[Docs from KeyCloak]('https://www.keycloak.org/getting-started/getting-started-docker)

Run command:
```text
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:21.0.2 start-dev
```

## Build Guide
* Go to root folder
```text
docker-compose up
./gradlew build
```
or
```text
gradle bootRun
```