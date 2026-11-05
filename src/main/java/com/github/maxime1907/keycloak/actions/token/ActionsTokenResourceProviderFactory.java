package com.github.maxime1907.keycloak.actions.token;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class ActionsTokenResourceProviderFactory implements RealmResourceProviderFactory {

    // Upper bound of the lifespan a caller can request, in seconds.
    static final int DEFAULT_MAX_LIFESPAN = 7 * 24 * 3600;

    private int maxLifespan = DEFAULT_MAX_LIFESPAN;

    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new ActionsTokenResourceProvider(keycloakSession, maxLifespan);
    }

    @Override
    public void init(Scope scope) {
        maxLifespan = scope.getInt("max-lifespan", DEFAULT_MAX_LIFESPAN);
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
        return ActionsTokenResourceProvider.ID;
    }
}
