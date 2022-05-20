# Simple extension for managing actions token in Keycloak

This PoC extension exposes a custom realm resource to manage action tokens.

## Build the example
```
mvn clean verify
```

## Deploy the example
Copy to the `standalone/deployments` directory in Keycloak.

## Routes

### Generate
```
POST /auth/realms/{realm}/actions-token/generate
```

#### Description
Request an action token for a set of specific actions.

#### Request
| Type | Name | Required | Description | Schema |
| :----: | --- | --- | --- | --- |
| Path | realm | true | realm name (not id!) | string |
| Body | user_id | true | User id | string |
| Body | actions | true | required actions the user needs to complete | < string > array |
| Body | lifespan | false | Number of seconds after which the generated token expires | integer(int32) |
| Body | client_id | false | Client id | string |
| Body | redirect_uri | false | Redirect uri | string |
| Body | redirect_uri_validate | false | Validate redirect uri | string |
#### Response
| Type | Name | Required | Description | Schema |
| :----: | --- | --- | --- | --- |
| Body | action_token | true | JWT action token | string |
#### Consumes
- `application/json`
#### Produces
- `application/json`
