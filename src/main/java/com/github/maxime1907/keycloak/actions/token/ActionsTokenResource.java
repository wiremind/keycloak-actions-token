
package com.github.maxime1907.keycloak.actions.token;

import java.util.LinkedList;
import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.TokenCategory;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;

import com.google.gson.Gson;

public class ActionsTokenResource {

    private final KeycloakSession session;

    private final static Logger logger = Logger.getLogger(ActionsTokenResource.class);

    private AdminPermissionEvaluator realmAuth;

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
        KeycloakContext context = session.getContext();

        RealmModel realm = session.getContext().getRealm();

        AdminAuth auth = authenticateRealmAdminRequest(context.getRequestHeaders());

        RealmManager realmManager = new RealmManager(session);
        if (realm == null) throw new NotFoundException("Realm not found.");

        if (!auth.getRealm().equals(realmManager.getKeycloakAdminstrationRealm())
                && !auth.getRealm().equals(realm)) {
            throw new org.keycloak.services.ForbiddenException();
        }

        realmAuth = AdminPermissions.evaluator(session, realm, auth);

        session.getContext().setRealm(realm);

        ActionTokenRequest actionTokenRequest = null;
        try {
            Gson gson = new Gson();
            actionTokenRequest = gson.fromJson(jsonString, ActionTokenRequest.class);        
        } catch (IllegalArgumentException cause) {
            throw new WebApplicationException(
                ErrorResponse.error("Invalid json input.", Status.BAD_REQUEST));
        }

        UserModel user = session.users().getUserById(realm, actionTokenRequest.userId);
        if (user == null) {
            // we do this to make sure somebody can't phish ids
            if (realmAuth.users().canQuery())
                throw new NotFoundException("User not found");
            else
                throw new ForbiddenException();
        }

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

        realmAuth.users().requireManage(user);

        if (requiredActions.contains(RequiredAction.VERIFY_EMAIL.name()) && user.getEmail() == null)
        {
            return ErrorResponse.error("User email missing", Status.BAD_REQUEST);
        }

        if (!user.isEnabled()) {
            throw new WebApplicationException(
                ErrorResponse.error("User is disabled", Status.BAD_REQUEST));
        }

        if (actionTokenRequest.redirectUri != null && actionTokenRequest.clientId == null) {
            throw new WebApplicationException(
                ErrorResponse.error("Client id missing", Status.BAD_REQUEST));
        }

        if (actionTokenRequest.clientId == null) {
            actionTokenRequest.clientId = Constants.ACCOUNT_MANAGEMENT_CLIENT_ID;
        }

        ClientModel client = assertValidClient(actionTokenRequest.clientId);
        if (actionTokenRequest.redirectUri != null && actionTokenRequest.redirectUriValidate != null && actionTokenRequest.redirectUriValidate)
            assertValidRedirectUri(actionTokenRequest.redirectUri, client);

        // /auth/admin/master/console/#/realms/master/token-settings User-Initiated Action Lifespan
        int validityInSecs = context.getRealm().getActionTokenGeneratedByAdminLifespan();
        if (actionTokenRequest.lifespan != null)
            validityInSecs = actionTokenRequest.lifespan;
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

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

    private ClientModel assertValidClient(String clientId) {
        ClientModel client = session.getContext().getRealm().getClientByClientId(clientId);
        if (client == null) {
            logger.debugf("Client %s doesn't exist", clientId);
            throw new WebApplicationException(
                ErrorResponse.error("Client doesn't exist", Status.BAD_REQUEST));
        }
        if (!client.isEnabled()) {
            logger.debugf("Client %s is not enabled", clientId);
            throw new WebApplicationException(
                    ErrorResponse.error("Client is not enabled", Status.BAD_REQUEST));
        }
        return client;
    }

    protected AdminAuth authenticateRealmAdminRequest(HttpHeaders headers) {
        String tokenString = AppAuthManager.extractAuthorizationHeaderToken(headers);
        if (tokenString == null) throw new NotAuthorizedException("Bearer");
        AccessToken token;
        try {
            JWSInput input = new JWSInput(tokenString);
            token = input.readJsonContent(AccessToken.class);
        } catch (JWSInputException e) {
            throw new NotAuthorizedException("Bearer token format error");
        }
        String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        if (realm == null) {
            throw new NotAuthorizedException("Unknown realm in token");
        }
        session.getContext().setRealm(realm);

        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session)
                .setRealm(realm)
                .setConnection(session.getContext().getConnection())
                .setHeaders(headers)
                .authenticate();

        if (authResult == null) {
            logger.debug("Token not valid");
            throw new NotAuthorizedException("Bearer");
        }

        ClientModel client = realm.getClientByClientId(token.getIssuedFor());
        if (client == null) {
            throw new NotFoundException("Could not find client for authorization");

        }

        return new AdminAuth(realm, authResult.getToken(), authResult.getUser(), client);
    }
}
