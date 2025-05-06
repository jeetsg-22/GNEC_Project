# Stage 1: Build the application using Maven
FROM maven:3.8-openjdk-17 as builder
# Set the working directory inside the container
WORKDIR /app
# Copy the pom.xml and src folder to the container
COPY pom.xml .
COPY src ./src
# Run Maven to build the project and create the JAR file, skipping tests
RUN mvn clean package -DskipTests

# Stage 2: Run the application using OpenJDK
FROM openjdk:17-slim
# Install curl and ffmpeg inside the container
RUN apt-get update && apt-get install -y curl ffmpeg
# Set the working directory inside the container
WORKDIR /app
# Copy the JAR file from the builder stage to the current image
COPY --from=builder /app/target/sampleGnec_1-0.0.1-SNAPSHOT.jar app.jar
# Expose the port for the Spring Boot application (default port for Spring Boot is 8080)
EXPOSE 8080
# Command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]

