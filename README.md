# Spring OAuth2 Project (May need fixes)

## Project structure
```text
auth-server
|
client-server
|
resource-server
```

Gradle multi-module enabled: [Gradle multi-module example]('https://github.com/ZQR0/gradle-multi-project-example-spring)

## About
* Authorization server (port :8081) - provides auth functionality
* Client server (port :8082) - provides client side
* Resource server (port :8083) - provides all resources

## Build Guide
* Go to root folder
```text
./gradlew build
```
or
```text
gradle bootRun
```