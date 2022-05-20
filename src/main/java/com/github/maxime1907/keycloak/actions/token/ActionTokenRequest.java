package com.github.maxime1907.keycloak.actions.token;

import java.util.List;

import com.google.gson.annotations.SerializedName;

public class ActionTokenRequest {
    // Required
    @SerializedName("user_id")
    String userId;

    @SerializedName("actions")
    List<String> actions;

    // Optional
    @SerializedName("redirect_uri")
    String redirectUri;

    @SerializedName("client_id")
    String clientId;

    @SerializedName("lifespan")
    Integer lifespan;

    @SerializedName("redirect_uri_validate")
    Boolean redirectUriValidate;
}
