
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

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.TokenCategory;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorResponse;

import com.google.gson.Gson;

import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class ActionsTokenResource {

    private final KeycloakSession session;

    public ActionsTokenResource(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @NoCache
    @Path("generate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getActionToken(
        String jsonString,
        @Context UriInfo uriInfo) {
        // if (this.auth == null || this.auth.getToken() == null) {
        //     throw new NotAuthorizedException("Bearer");
        // }

        ActionTokenRequest actionTokenRequest = null;
        try {
            Gson gson = new Gson();
            actionTokenRequest = gson.fromJson(jsonString, ActionTokenRequest.class);        
        } catch (IllegalArgumentException cause) {
            throw new WebApplicationException(
                ErrorResponse.error("Invalid json input.", Status.BAD_REQUEST));
        }

        log.debugf("%s", actionTokenRequest.userId);
        log.debugf("%s", actionTokenRequest.redirectUri);
        log.debugf("%s", actionTokenRequest.clientId);
        log.debugf("%s", actionTokenRequest.actions);
        log.debugf("%s", actionTokenRequest.redirectUriValidate);
        log.debugf("%s", actionTokenRequest.lifespan);

        KeycloakContext context = session.getContext();

        if (actionTokenRequest.redirectUri != null && actionTokenRequest.clientId == null) {
            throw new WebApplicationException(
                ErrorResponse.error("Client id missing", Status.BAD_REQUEST));
        }

        if (actionTokenRequest.clientId == null) {
            actionTokenRequest.clientId = Constants.ACCOUNT_MANAGEMENT_CLIENT_ID;
        }

        ClientModel client = assertValidClient(actionTokenRequest.clientId, context);
        if (actionTokenRequest.redirectUri != null && actionTokenRequest.redirectUriValidate != null && actionTokenRequest.redirectUriValidate)
            assertValidRedirectUri(actionTokenRequest.redirectUri, client);

        // /auth/admin/master/console/#/realms/master/token-settings User-Initiated Action Lifespan
        int validityInSecs = context.getRealm().getActionTokenGeneratedByAdminLifespan();
        if (actionTokenRequest.lifespan != null)
            validityInSecs = actionTokenRequest.lifespan;
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

        // Can parameterize this as well
        List<String> requiredActions = new LinkedList<String>();

        try {
            for (int i = 0; i < actionTokenRequest.actions.size(); i++) {
                String requiredActionName = actionTokenRequest.actions.get(i);
                RequiredAction requiredAction = RequiredAction.valueOf(requiredActionName);
                requiredActions.add(requiredAction.name());
            }
        } catch (IllegalArgumentException cause) {
            throw new WebApplicationException(
                ErrorResponse.error("Invalid requiredAction.", Status.BAD_REQUEST));
        }

        ExecuteActionsActionToken token = new ExecuteActionsActionToken(
            actionTokenRequest.userId,
            absoluteExpirationInSecs,
            requiredActions,
            actionTokenRequest.redirectUri,
            actionTokenRequest.clientId
        ){
            @Override
            public TokenCategory getCategory() {
                return TokenCategory.ADMIN;
            }
        };

        String tokenKey = token.serialize(
            session,
            context.getRealm(),
            uriInfo
        );

        Gson gson = new Gson();
        ActionToken actionToken = new ActionToken(tokenKey);
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

    private ClientModel assertValidClient(String clientId, KeycloakContext context) {
        ClientModel client = context.getRealm().getClientByClientId(clientId);
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
}