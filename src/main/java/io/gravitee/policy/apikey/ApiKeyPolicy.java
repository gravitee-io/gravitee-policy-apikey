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

import static io.gravitee.gateway.jupiter.api.context.ExecutionContext.*;

import io.gravitee.common.http.GraviteeHttpHeader;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.jupiter.api.ExecutionFailure;
import io.gravitee.gateway.jupiter.api.context.ExecutionContext;
import io.gravitee.gateway.jupiter.api.context.Request;
import io.gravitee.gateway.jupiter.api.context.RequestExecutionContext;
import io.gravitee.gateway.jupiter.api.policy.SecurityPolicy;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.gravitee.policy.v3.apikey.ApiKeyPolicyV3;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.model.ApiKey;
import io.reactivex.Completable;
import io.reactivex.Single;
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

    private static final Logger log = LoggerFactory.getLogger(ApiKeyPolicy.class);

    static final String ATTR_API_KEY = ATTR_PREFIX + "api-key";
    static final String ATTR_INTERNAL_API_KEY = ATTR_INTERNAL_PREFIX + "api-key";

    protected static final String API_KEY_MISSING_KEY = "API_KEY_MISSING";
    protected static final String API_KEY_INVALID_KEY = "API_KEY_INVALID";

    static String API_KEY_HEADER, API_KEY_QUERY_PARAMETER;
    static final String API_KEY_HEADER_PROPERTY = "policy.api-key.header";
    static final String API_KEY_QUERY_PARAMETER_PROPERTY = "policy.api-key.param";
    static final String DEFAULT_API_KEY_QUERY_PARAMETER = "api-key";
    static final String DEFAULT_API_KEY_HEADER_PARAMETER = GraviteeHttpHeader.X_GRAVITEE_API_KEY;

    private final boolean propagateApiKey;

    public ApiKeyPolicy(ApiKeyPolicyConfiguration configuration) {
        super(configuration);
        this.propagateApiKey = configuration != null && configuration.isPropagateApiKey();
    }

    @Override
    public String id() {
        return "api-key";
    }

    /**
     * {@inheritDoc}
     * The {@link ApiKeyPolicy} is assignable if an api key is passed in the request headers.
     */
    @Override
    public Single<Boolean> support(RequestExecutionContext ctx) {
        final Optional<String> optApiKey = extractApiKey(ctx);

        optApiKey.ifPresent(apiKey -> ctx.setInternalAttribute(ATTR_INTERNAL_API_KEY, apiKey));

        return Single.just(optApiKey.isPresent());
    }

    /**
     * {@inheritDoc}
     * Do not validate the subscription because the api key already has everything needed to check expiration.
     *
     * @return <code>false</code>, indicating that the subscription must not be validated as it is already performed.
     */
    @Override
    public boolean requireSubscription() {
        return false;
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
    public Completable onRequest(RequestExecutionContext ctx) {
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
                        .getComponent(ApiKeyRepository.class)
                        .findByKeyAndApi(requestApiKey.get(), ctx.getAttribute(ATTR_API));

                    if (apiKeyOpt.isPresent()) {
                        ApiKey apiKey = apiKeyOpt.get();

                        // Add data about api-key, plan, application and subscription into the execution context.
                        ctx.setAttribute(ATTR_APPLICATION, apiKey.getApplication());
                        ctx.setAttribute(ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
                        ctx.setAttribute(ATTR_PLAN, apiKey.getPlan());
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

    private boolean isApiKeyValid(RequestExecutionContext ctx, ApiKey apiKey) {
        return !apiKey.isRevoked() && (apiKey.getExpireAt() == null || apiKey.getExpireAt().after(new Date(ctx.request().timestamp())));
    }

    private Completable interrupt401(RequestExecutionContext ctx, String key, String message) {
        return ctx.interruptWith(new ExecutionFailure(HttpStatusCode.UNAUTHORIZED_401).key(key).message(message));
    }

    private Optional<String> extractApiKey(RequestExecutionContext ctx) {
        // 1_ First, check if already resolved.
        String apiKey = ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY);
        if (apiKey != null) {
            return Optional.of(apiKey);
        }

        final Request request = ctx.request();

        // 2_ Second, search in HTTP headers
        apiKey = request.headers().get(API_KEY_HEADER);
        if (apiKey != null) {
            return Optional.of(apiKey);
        }

        // 3_ If not found, search in query parameters
        apiKey = request.parameters().getFirst(API_KEY_QUERY_PARAMETER);

        return Optional.ofNullable(apiKey);
    }

    private void cleanupApiKey(RequestExecutionContext ctx) {
        if (!propagateApiKey) {
            ctx.request().headers().remove(API_KEY_HEADER);
            ctx.request().parameters().remove(API_KEY_QUERY_PARAMETER);
            ctx.removeInternalAttribute(ATTR_INTERNAL_API_KEY);
        }
    }
}
