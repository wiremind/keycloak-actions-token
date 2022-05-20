package com.github.maxime1907.keycloak.actions.token;

import java.util.List;

public class ActionTokenRequest {
    String userId;
    String email;
    String redirectUri;
    String clientId;
    List<String> requiredActions;
    Boolean checkRedirectUri;
}
