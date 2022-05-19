package com.github.maxime1907.keycloak.actions.token;

public class ActionTokenRequest {
    String userId;
    String email;
    String redirectUri;
    String clientId;
    String requiredAction;
    Boolean checkRedirectUri;
}
