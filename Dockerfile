# ---- Stage 1: Compile ZeroCrypt.java ----
FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /src
COPY ZeroCrypt.java .
RUN javac ZeroCrypt.java


# ---- Stage 2: Run ZeroCrypt ----
FROM eclipse-temurin:21-jre-alpine

WORKDIR /data

# ⬇️ COPY ALL .class FILES, not just ZeroCrypt.class
COPY --from=build /src/*.class /opt/zerocrypt/

ENTRYPOINT ["java", "-cp", "/opt/zerocrypt", "ZeroCrypt"]
