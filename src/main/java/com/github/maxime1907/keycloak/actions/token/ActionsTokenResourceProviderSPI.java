package com.github.maxime1907.keycloak.actions.token;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.keycloak.services.resource.RealmResourceSPI;

public class ActionsTokenResourceProviderSPI extends RealmResourceSPI {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "Action Token Provider";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return RealmResourceProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return RealmResourceProviderFactory.class;
    }
}
