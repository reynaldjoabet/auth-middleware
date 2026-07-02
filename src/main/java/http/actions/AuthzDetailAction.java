package http.actions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import auth.OAuthAttrs;
import auth.Principal;
import auth.SecurityAttrs;
import auth.annotation.RequireAuthzDetail;
import jakarta.inject.Inject;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Validates the {@code authorization_details} claim per RFC 9396 (Rich
 * Authorization Requests): the token must carry an entry matching the required
 * type whose actions and locations cover the annotation's requirements. The
 * matched entry is attached as {@code OAuthAttrs.AUTHZ_DETAIL} for the
 * controller to enforce instance-level rules (amounts, account ids, …).
 * Must be composed after {@code @RequireOAuth2}.
 */
public class AuthzDetailAction extends Action<RequireAuthzDetail> {

    private final ObjectMapper mapper;

    @Inject
    public AuthzDetailAction(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public CompletionStage<Result> call(Http.Request req) {

        Optional<Principal> principal = req.attrs().getOptional(SecurityAttrs.PRINCIPAL);
        if (principal.isEmpty()) {
            return forbiddenResult("No token claims found — @RequireOAuth2 must precede @RequireAuthzDetail");
        }

        Object rawDetails = principal.get().raw.getClaim("authorization_details");
        if (rawDetails == null) {
            return forbiddenResult("Token does not contain authorization_details");
        }

        try {
            JsonNode detailsArray = mapper.valueToTree(rawDetails);
            if (!detailsArray.isArray()) {
                return forbiddenResult("authorization_details must be a JSON array");
            }

            String requiredType = configuration.type();
            List<String> requiredActions = Arrays.asList(configuration.actions());
            List<String> requiredLocations = Arrays.asList(configuration.locations());

            for (JsonNode detail : detailsArray) {
                if (!requiredType.equals(detail.path("type").asText())) {
                    continue;
                }
                if (!requiredActions.isEmpty()
                        && !asTextList(detail.path("actions")).containsAll(requiredActions)) {
                    continue;
                }
                if (!requiredLocations.isEmpty()
                        && !asTextList(detail.path("locations")).containsAll(requiredLocations)) {
                    continue;
                }

                Http.Request enriched = req.addAttr(OAuthAttrs.AUTHZ_DETAIL, detail.toString());
                return delegate.call(enriched);
            }

            return forbiddenResult("No matching authorization_details entry for type=" + requiredType);

        } catch (RuntimeException e) {
            return forbiddenResult("Failed to parse authorization_details");
        }
    }

    private static List<String> asTextList(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(node -> values.add(node.asText()));
        return values;
    }

    private static CompletionStage<Result> forbiddenResult(String desc) {
        return CompletableFuture.completedFuture(
                Results.forbidden().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                        "Bearer error=\"insufficient_authorization_details\", "
                                + "error_description=\"" + desc + "\""));
    }
}
