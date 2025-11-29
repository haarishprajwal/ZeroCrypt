FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /src
COPY ZeroCrypt.java .
RUN javac ZeroCrypt.java


FROM eclipse-temurin:21-jre-alpine

WORKDIR /data

COPY --from=build /src/*.class /opt/zerocrypt/

ENTRYPOINT ["java", "-cp", "/opt/zerocrypt", "ZeroCrypt"]
