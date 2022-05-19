package com.github.maxime1907.keycloak.actions.token;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class ActionsTokenResourceProviderFactory implements RealmResourceProviderFactory {

    private ActionsTokenResourceProvider actionsTokenResourceProvider;

    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        if (actionsTokenResourceProvider == null) {
            actionsTokenResourceProvider = new ActionsTokenResourceProvider(keycloakSession);
        }
        return actionsTokenResourceProvider;
    }

    @Override
    public void init(Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public String getId() {
        return "actions-token";
    }
}
