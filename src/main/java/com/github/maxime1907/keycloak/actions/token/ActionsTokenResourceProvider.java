package com.github.maxime1907.keycloak.actions.token;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;


public class ActionsTokenResourceProvider implements RealmResourceProvider {

    // The ID of the provider is also used as the name of the endpoint
    public final static String ID = "actions-token";

    private KeycloakSession session;

    public ActionsTokenResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        // RealmModel realm = session.getContext().getRealm();
        ActionsTokenResource actionToken = new ActionsTokenResource(this.session);
        return actionToken;
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
