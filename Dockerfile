# Stage 1: Build the application using Maven
FROM maven:3.8-openjdk-17 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy only pom.xml first to leverage Docker cache for dependencies
COPY pom.xml .

# Download dependencies in a separate layer to leverage caching
RUN mvn dependency:go-offline

# Copy the entire project
COPY . .

# Build the application, skip tests, and clean up local Maven cache
RUN mvn clean package -DskipTests && \
    rm -rf /root/.m2/repository

# Stage 2: Create a lightweight runtime image
FROM eclipse-temurin:17-jre

# Optional: If you still want a smaller image, use `17-jre-slim`, but make sure it's available on Docker Hub
# FROM eclipse-temurin:17-jre-slim

# Install curl and ffmpeg with cleanup in the same layer to reduce image size
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ffmpeg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the built JAR file from the builder stage
COPY --from=builder /app/target/sampleGnec_1-0.0.1-SNAPSHOT.jar app.jar

# Expose the port the app runs on
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
