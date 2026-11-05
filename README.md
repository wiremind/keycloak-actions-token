# Keycloak actions token

This extension exposes a custom realm resource to manage action tokens in keycloak.

## Build the example
```
mvn clean verify
```

The build writes `target/actions-token-<version>.jar`.
Without a local Java 21, build in a container:

```
docker run --rm -v "$PWD":/src -w /src maven:3-eclipse-temurin-21 mvn clean verify
```

Each pull request also uploads this JAR as a workflow artifact.

## Deploy the example
### Wildfly
Copy the `.jar` into the keycloak directory `standalone/deployments`
### Quarkus
Copy the `.jar` into the keycloak directory `providers`

## Routes

### Generate
#### Wildfly
```
POST /auth/realms/{realm}/actions-token/generate
```
#### Quarkus
```
POST /realms/{realm}/actions-token/generate
```

#### Description
Request an action token for a set of specific actions.

#### Request
| Type | Name | Required | Description | Schema |
| :----: | --- | --- | --- | --- |
| Path | realm | true | realm name (not id!) | string |
| Body | user_id | true | User that will be asked to perform a set of required actions | string |
| Body | actions | true | Required actions the user needs to complete. List of [required actions here](https://www.keycloak.org/docs-api/16.0/javadocs/org/keycloak/models/UserModel.RequiredAction.html) | < string > array |
| Body | lifespan | false | Number of seconds after which the generated token expires | integer(int32) |
| Body | client_id | false | OAuth client the token was issued for. Defaults to the `account` client. | string |
| Body | redirect_uri | false | If no redirect is given, then there will be no link back to click after actions have completed. Redirect uri must be a valid uri for the particular `client_id` | string |
| Body | redirect_uri_validate | false | Bypass `redirect_uri` validation checks for the particular `client_id` | boolean |
#### Response
| Type | Name | Required | Description | Schema |
| :----: | --- | --- | --- | --- |
| Body | action_token | true | JWT action token signed with the realm's default signature algorithm | string |
#### Consumes
- `application/json`
#### Produces
- `application/json`

## Releasing

[release-please](https://github.com/googleapis/release-please) makes the releases from the
[Conventional Commits](https://www.conventionalcommits.org/) on `master`:

1. A merge to `master` with a `feat:` or `fix:` commit opens or updates a release pull request.
   This pull request sets the next version in `pom.xml` and adds the changes to `CHANGELOG.md`.
2. A merge of the release pull request creates the tag `<version>` and the GitHub release.
3. The `Release` workflow then builds the JAR from the tag and attaches two assets to the release:
   `actions-token-<version>.jar` and its `.sha256` file.

`feat:` increments the minor version and `fix:` increments the patch version.
Before 1.0.0, a breaking change (`feat!:`) also increments the minor version.
`chore:`, `ci:`, `docs:` and `test:` commits do not cause a release.

Renovate keeps the Maven dependencies, the Maven plugins and the GitHub Actions up to date.
Its pull requests use `fix(deps):` for the dependencies, so each merge causes a release.

## Useful resources
- https://github.com/aerogear/keycloak-metrics-spi
- https://github.com/thomasdarimont/keycloak-avatar-minio-extension
- https://github.com/keycloak/keycloak-quickstarts/tree/latest/action-token-authenticator
- https://www.janua.fr/action-token-in-keycloak/
- https://stackoverflow.com/questions/67006007/how-to-generate-and-use-login-action-token-for-keycloak-user-update-profile-in-e
- https://github.com/keycloak/keycloak/blob/264c5a6cdb2fb86e20536ea4302d20160ca01919/services/src/main/java/org/keycloak/services/resources/admin/UserResource.java#L826
- https://stackoverflow.com/a/67636834
- https://github.com/dteleguin/beercloak/blob/master/beercloak-module/src/main/java/beercloak/providers/BeerResourceProvider.java
- https://github.com/dteleguin/beercloak/blob/master/beercloak-module/src/main/java/beercloak/resources/AbstractAdminResource.java
- https://github.com/keycloak/keycloak/blob/1ed81fa3772220cb8018654e40645f981c934da6/services/src/main/java/org/keycloak/services/resources/admin/AdminRoot.java#L156
- https://github.com/keycloak/keycloak/blob/264c5a6cdb2fb86e20536ea4302d20160ca01919/services/src/main/java/org/keycloak/services/resources/admin/UsersResource.java#L284
