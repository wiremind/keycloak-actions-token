FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /home/app/src

COPY . /home/app/src
RUN mvn clean verify

RUN mvn -q -Dexec.executable=echo -Dexec.args='${project.artifactId}-${project.version}.jar' --non-recursive exec:exec > /home/app/src/release-fullname.txt

FROM alpine:3

WORKDIR /release

COPY --from=build /home/app/src/release-fullname.txt /tmp/release-fullname.txt

COPY --from=build /home/app/src/target /release/target

RUN PACKAGE_NAME=`cat /tmp/release-fullname.txt` && cp "/release/target/${PACKAGE_NAME}" "/release/${PACKAGE_NAME}"

RUN rm -rf /release/target && rm -f /tmp/release-fullname.txt
