/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.apikey;

import io.gravitee.common.http.GraviteeHttpHeader;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.service.ApiKey;
import io.gravitee.gateway.api.service.ApiKeyService;
import io.gravitee.gateway.jupiter.api.ExecutionFailure;
import io.gravitee.gateway.jupiter.api.context.ContextAttributes;
import io.gravitee.gateway.jupiter.api.context.HttpExecutionContext;
import io.gravitee.gateway.jupiter.api.context.HttpRequest;
import io.gravitee.gateway.jupiter.api.policy.SecurityPolicy;
import io.gravitee.gateway.jupiter.api.policy.SecurityToken;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.gravitee.policy.v3.apikey.ApiKeyPolicyV3;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import java.util.Date;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ApiKeyPolicy extends ApiKeyPolicyV3 implements SecurityPolicy {

    static final String ATTR_API_KEY = ContextAttributes.ATTR_PREFIX + "api-key";
    static final String ATTR_INTERNAL_API_KEY = "api-key";
    static final String API_KEY_HEADER_PROPERTY = "policy.api-key.header";
    static final String API_KEY_QUERY_PARAMETER_PROPERTY = "policy.api-key.param";
    static final String DEFAULT_API_KEY_QUERY_PARAMETER = "api-key";
    static final String DEFAULT_API_KEY_HEADER_PARAMETER = GraviteeHttpHeader.X_GRAVITEE_API_KEY;
    private static final Logger log = LoggerFactory.getLogger(ApiKeyPolicy.class);
    static String API_KEY_HEADER, API_KEY_QUERY_PARAMETER;
    private final boolean propagateApiKey;

    public ApiKeyPolicy(ApiKeyPolicyConfiguration configuration) {
        super(configuration);
        this.propagateApiKey = configuration != null && configuration.isPropagateApiKey();
    }

    @Override
    public String id() {
        return "api-key";
    }

    @Override
    public Maybe<SecurityToken> extractSecurityToken(HttpExecutionContext ctx) {
        final Optional<String> apiKey = extractApiKey(ctx);
        if (apiKey.isPresent()) {
            ctx.setInternalAttribute(ATTR_INTERNAL_API_KEY, apiKey.get());
            return Maybe.just(SecurityToken.forApiKey(apiKey.get()));
        }
        return Maybe.empty();
    }

    /**
     * {@inheritDoc}
     * Validate the subscription, as a valid shared API key can be linked to a closed or expired subscription.
     *
     * @return <code>true</code>, indicating that the subscription must be validated.
     */
    @Override
    public boolean requireSubscription() {
        return true;
    }

    /**
     * Order set to 500 to make sure it will be executed before lower security policies such a Keyless but after higher security policies such as Jwt or OAuth2.
     *
     * @return 500
     */
    @Override
    public int order() {
        return 500;
    }

    @Override
    public Completable onRequest(final HttpExecutionContext ctx) {
        return handleSecurity(ctx);
    }

    private Completable handleSecurity(final HttpExecutionContext ctx) {
        return Completable
            .defer(() -> {
                try {
                    Optional<String> requestApiKey = extractApiKey(ctx);

                    if (requestApiKey.isEmpty()) {
                        // The api key is required
                        return interrupt401(
                            ctx,
                            API_KEY_MISSING_KEY,
                            "No API Key has been specified in headers (" +
                            API_KEY_HEADER +
                            ") or query parameters (" +
                            API_KEY_QUERY_PARAMETER +
                            ")."
                        );
                    }

                    final Optional<ApiKey> apiKeyOpt = ctx
                        .getComponent(ApiKeyService.class)
                        .getByApiAndKey(ctx.getAttribute(ContextAttributes.ATTR_API), requestApiKey.get());

                    if (apiKeyOpt.isPresent()) {
                        ApiKey apiKey = apiKeyOpt.get();

                        // Add data about api-key, plan, application and subscription into the execution context.
                        ctx.setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
                        ctx.setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
                        ctx.setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
                        ctx.setAttribute(ATTR_API_KEY, apiKey.getKey());

                        if (isApiKeyValid(ctx, apiKey)) {
                            return Completable.complete();
                        }
                    }
                } catch (Throwable t) {
                    log.warn("An exception occurred when trying to verify apikey.", t);
                }

                return interrupt401(ctx, API_KEY_INVALID_KEY, "API Key is not valid or is expired / revoked.");
            })
            .doOnTerminate(() -> cleanupApiKey(ctx));
    }

    private boolean isApiKeyValid(HttpExecutionContext ctx, ApiKey apiKey) {
        return !apiKey.isRevoked() && (apiKey.getExpireAt() == null || apiKey.getExpireAt().after(new Date(ctx.request().timestamp())));
    }

    private Completable interrupt401(HttpExecutionContext ctx, String key, String message) {
        return ctx.interruptWith(new ExecutionFailure(HttpStatusCode.UNAUTHORIZED_401).key(key).message(message));
    }

    private Optional<String> extractApiKey(HttpExecutionContext ctx) {
        // 1_ First, check if already resolved.
        String apiKey = ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY);
        if (apiKey != null) {
            return Optional.of(apiKey);
        }

        final HttpRequest request = ctx.request();

        // 2_ Second, search in HTTP headers
        apiKey = request.headers().get(API_KEY_HEADER);
        if (apiKey != null) {
            return Optional.of(apiKey);
        }

        // 3_ If not found, search in query parameters
        apiKey = request.parameters().getFirst(API_KEY_QUERY_PARAMETER);

        return Optional.ofNullable(apiKey);
    }

    private void cleanupApiKey(HttpExecutionContext ctx) {
        if (!propagateApiKey) {
            ctx.request().headers().remove(API_KEY_HEADER);
            ctx.request().parameters().remove(API_KEY_QUERY_PARAMETER);
        }
        ctx.removeInternalAttribute(ATTR_INTERNAL_API_KEY);
    }
}
