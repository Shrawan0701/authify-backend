
FROM openjdk:17-jdk-slim as builder


WORKDIR /app


COPY pom.xml .
COPY src ./src


RUN ./mvnw clean install -DskipTests --no-transfer-progress


FROM openjdk:17-jdk-slim


WORKDIR /app


COPY --from=builder /app/target/authify-0.0.1-SNAPSHOT.jar app.jar


EXPOSE 8080


ENTRYPOINT ["java", "-jar", "app.jar"]