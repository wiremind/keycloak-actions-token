package com.github.maxime1907.keycloak.actions.token;

import java.util.LinkedList;
import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import com.google.gson.Gson;

import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resource.RealmResourceProvider;

import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class ActionsTokenResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public ActionsTokenResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @Path("generate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getActionToken(
        String jsonString,
        @Context UriInfo uriInfo) {
        ActionTokenRequest actionTokenRequest = null;
        try {
            Gson gson = new Gson();
            actionTokenRequest = gson.fromJson(jsonString, ActionTokenRequest.class);        
        } catch (IllegalArgumentException cause) {
            throw new WebApplicationException(
                ErrorResponse.error("Invalid json input.", Status.BAD_REQUEST));
        }

        log.debugf("%s", actionTokenRequest.userId);
        log.debugf("%s", actionTokenRequest.email);
        log.debugf("%s", actionTokenRequest.redirectUri);
        log.debugf("%s", actionTokenRequest.clientId);
        log.debugf("%s", actionTokenRequest.requiredAction);
        log.debugf("%s", actionTokenRequest.checkRedirectUri);

        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        int validityInSecs = realm.getActionTokenGeneratedByUserLifespan();
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

        ClientModel client = assertValidClient(actionTokenRequest.clientId, realm);

        if (actionTokenRequest.checkRedirectUri)
            assertValidRedirectUri(actionTokenRequest.redirectUri, client);

        // Can parameterize this as well
        List<String> requiredActions = new LinkedList<String>();
        RequiredAction requiredAction = null;
        try {
            requiredAction = RequiredAction.valueOf(actionTokenRequest.requiredAction);
        } catch (IllegalArgumentException cause) {
            throw new WebApplicationException(
                ErrorResponse.error("Invalid requiredAction.", Status.BAD_REQUEST));
        }

        requiredActions.add(requiredAction.name());

        String token = new ExecuteActionsActionToken(
            actionTokenRequest.userId,
            absoluteExpirationInSecs,
            requiredActions,
            actionTokenRequest.redirectUri,
            actionTokenRequest.clientId
        ).serialize(
            session,
            context.getRealm(),
            uriInfo
        );

        Gson gson = new Gson();
        ActionToken actionToken = new ActionToken(token);
        String jsonInString = gson.toJson(actionToken);
        return Response.status(200).entity(jsonInString).build();
    }

    private void assertValidRedirectUri(String redirectUri, ClientModel client) {
        String redirect = RedirectUtils.verifyRedirectUri(session, redirectUri, client);
        if (redirect == null) {
            throw new WebApplicationException(
                ErrorResponse.error("Invalid redirect uri.", Status.BAD_REQUEST));
        }
    }

    private ClientModel assertValidClient(String clientId, RealmModel realm) {
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            log.debugf("Client %s doesn't exist", clientId);
            throw new WebApplicationException(
                ErrorResponse.error("Client doesn't exist", Status.BAD_REQUEST));
        }
        if (!client.isEnabled()) {
            log.debugf("Client %s is not enabled", clientId);
            throw new WebApplicationException(
                    ErrorResponse.error("Client is not enabled", Status.BAD_REQUEST));
        }
        return client;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
