package com.github.maxime1907.keycloak.actions.token;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;


public class ActionsTokenResourceProvider implements RealmResourceProvider {

    // The ID of the provider is also used as the name of the endpoint
    public final static String ID = "actions-token";

    private KeycloakSession session;

    private final int maxLifespan;

    public ActionsTokenResourceProvider(KeycloakSession session, int maxLifespan) {
        this.session = session;
        this.maxLifespan = maxLifespan;
    }

    @Override
    public Object getResource() {
        // RealmModel realm = session.getContext().getRealm();
        ActionsTokenResource actionToken = new ActionsTokenResource(this.session, this.maxLifespan);
        return actionToken;
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
