# Changelog

## [0.1.0](https://github.com/wiremind/keycloak-actions-token/compare/0.0.12...0.1.0) (2026-11-05)


### ⚠ BREAKING CHANGES

* a request with an invalid redirect_uri and no redirect_uri_validate now fails. A lifespan above 7 days fails unless max-lifespan allows it.

### Bug Fixes

* harden the generate endpoint ([aa8702e](https://github.com/wiremind/keycloak-actions-token/commit/aa8702e3992a222e0ed985162fde4fe14995c059))

## [0.0.12](https://github.com/wiremind/keycloak-actions-token/compare/0.0.11...0.0.12) (2026-11-05)


### Bug Fixes

* use the AuthResult record accessors ([1111c69](https://github.com/wiremind/keycloak-actions-token/commit/1111c69236dccd523ac48300752715670ee2c5ca))
* use the AuthResult record accessors ([170ee16](https://github.com/wiremind/keycloak-actions-token/commit/170ee16afae23a192231966d52e14a18e5eddf93))
