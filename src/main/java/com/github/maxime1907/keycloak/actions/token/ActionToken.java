package com.github.maxime1907.keycloak.actions.token;

import com.google.gson.annotations.SerializedName;

public class ActionToken {
    @SerializedName("action_token")
    String actionToken;

    public ActionToken(String token) {
        this.actionToken = token;
    }
}
