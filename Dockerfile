FROM openjdk:17-jdk-slim as builder
WORKDIR /app

COPY pom.xml .
COPY src ./src
COPY .mvn .mvn
COPY mvnw .
COPY mvnw.cmd .

RUN chmod +x mvnw # <--- ADD THIS LINE: Make mvnw executable

RUN ./mvnw clean install -DskipTests --no-transfer-progress

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=builder /app/target/authify-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

RUN printenv > /tmp/env_vars.txt && cat /tmp/env_vars.txt

ENTRYPOINT ["java", "-jar", "app.jar"]
