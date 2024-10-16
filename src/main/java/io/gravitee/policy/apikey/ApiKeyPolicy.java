/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.apikey;

import static io.gravitee.gateway.reactive.api.policy.SecurityToken.TokenType.API_KEY;
import static io.gravitee.gateway.reactive.api.policy.SecurityToken.TokenType.MD5_API_KEY;

import io.gravitee.common.http.GraviteeHttpHeader;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.service.ApiKey;
import io.gravitee.gateway.api.service.ApiKeyService;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.ContextAttributes;
import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.gravitee.gateway.reactive.api.context.kafka.KafkaConnectionContext;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.gateway.reactive.api.policy.http.HttpSecurityPolicy;
import io.gravitee.gateway.reactive.api.policy.kafka.KafkaSecurityPolicy;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.gravitee.policy.v3.apikey.ApiKeyPolicyV3;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Optional;
import java.util.function.Function;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.ScramCredentialCallback;
import org.apache.kafka.common.security.scram.internals.ScramFormatter;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@Slf4j
public class ApiKeyPolicy extends ApiKeyPolicyV3 implements HttpSecurityPolicy, KafkaSecurityPolicy {

    static final String ATTR_API_KEY = ContextAttributes.ATTR_PREFIX + "api-key";
    static final String ATTR_INTERNAL_API_KEY = "api-key";
    static final String ATTR_INTERNAL_MD5_API_KEY = "md5-api-key";
    static final String API_KEY_HEADER_PROPERTY = "policy.api-key.header";
    static final String API_KEY_QUERY_PARAMETER_PROPERTY = "policy.api-key.param";
    static final String DEFAULT_API_KEY_QUERY_PARAMETER = "api-key";
    static final String DEFAULT_API_KEY_HEADER_PARAMETER = GraviteeHttpHeader.X_GRAVITEE_API_KEY;
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
    public Maybe<SecurityToken> extractSecurityToken(HttpPlainExecutionContext ctx) {
        final Optional<String> apiKeyOpt = extractApiKey(ctx);
        if (apiKeyOpt.isPresent()) {
            String apiKey = apiKeyOpt.get();
            if (apiKey.isBlank()) {
                return Maybe.just(SecurityToken.invalid(API_KEY));
            }
            ctx.setInternalAttribute(ATTR_INTERNAL_API_KEY, apiKey);
            return Maybe.just(SecurityToken.forApiKey(apiKey));
        }
        return Maybe.empty();
    }

    /**
     * {@inheritDoc}
     * Validate the subscription, as a valid shared API Key can be linked to a closed or expired subscription.
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
    public Completable onRequest(final HttpPlainExecutionContext ctx) {
        return handleSecurity(ctx);
    }

    private Completable handleSecurity(final HttpPlainExecutionContext ctx) {
        return Completable
            .defer(() -> {
                try {
                    Optional<String> requestApiKey = extractApiKey(ctx);

                    if (requestApiKey.isEmpty()) {
                        // The API Key is required
                        return interrupt401(ctx, API_KEY_MISSING_KEY);
                    }

                    final Optional<ApiKey> apiKeyOpt = ctx
                        .getComponent(ApiKeyService.class)
                        .getByApiAndKey(ctx.getAttribute(ContextAttributes.ATTR_API), requestApiKey.get());

                    if (this.handleApiKey(apiKeyOpt, ctx, (apiKey -> true))) {
                        return Completable.complete();
                    }
                } catch (Throwable t) {
                    log.warn("An exception occurred when trying to verify apikey.", t);
                }

                return interrupt401(ctx, API_KEY_INVALID_KEY);
            })
            .doOnTerminate(() -> cleanupApiKey(ctx));
    }

    private boolean isApiKeyValid(BaseExecutionContext ctx, ApiKey apiKey) {
        return !apiKey.isRevoked() && (apiKey.getExpireAt() == null || apiKey.getExpireAt().after(new Date(ctx.timestamp())));
    }

    private Completable interrupt401(HttpPlainExecutionContext ctx, String key) {
        return ctx.interruptWith(new ExecutionFailure(HttpStatusCode.UNAUTHORIZED_401).key(key).message(API_KEY_UNAUTHORIZED_MESSAGE));
    }

    private Optional<String> extractApiKey(HttpPlainExecutionContext ctx) {
        // 1_ First, check if already resolved.
        String apiKey = ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY);
        if (apiKey != null) {
            return Optional.of(apiKey);
        }

        final HttpPlainRequest request = ctx.request();

        // 2_ Second, search in HTTP headers
        if (request.headers().contains(API_KEY_HEADER)) {
            apiKey = request.headers().get(API_KEY_HEADER);
            if (apiKey == null) {
                // Header is present but empty so init apiKey with empty string
                apiKey = "";
            }
        }

        // 3_ If not found, search in query parameters
        if (apiKey == null && request.parameters().containsKey(API_KEY_QUERY_PARAMETER)) {
            apiKey = request.parameters().getFirst(API_KEY_QUERY_PARAMETER);
            if (apiKey == null) {
                // Header is present but empty so init apiKey with empty string
                apiKey = "";
            }
        }

        return Optional.ofNullable(apiKey);
    }

    private void cleanupApiKey(HttpPlainExecutionContext ctx) {
        if (!propagateApiKey) {
            ctx.request().headers().remove(API_KEY_HEADER);
            ctx.request().parameters().remove(API_KEY_QUERY_PARAMETER);
        }
        ctx.removeInternalAttribute(ATTR_INTERNAL_API_KEY);
    }

    @Override
    public Maybe<SecurityToken> extractSecurityToken(KafkaConnectionContext ctx) {
        Callback[] callbacks = ctx.callbacks();
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback nameCallback) {
                // With SASL_PLAIN or SCRAM, we expect the username to be a md5 hash of the api-key, for security and privacy.
                String md5ApiKey = nameCallback.getName();
                if (md5ApiKey != null && !md5ApiKey.isBlank()) {
                    ctx.setInternalAttribute(ATTR_INTERNAL_MD5_API_KEY, md5ApiKey);
                    return Maybe.just(SecurityToken.forMD5ApiKey(md5ApiKey));
                }
                return Maybe.just(SecurityToken.invalid(MD5_API_KEY));
            }
        }
        return Maybe.empty();
    }

    @Override
    public Completable authenticate(KafkaConnectionContext ctx) {
        return Completable
            .defer(() -> {
                String md5ApiKey = ctx.getInternalAttribute(ATTR_INTERNAL_MD5_API_KEY);
                final Optional<ApiKey> apiKeyOpt = ctx
                    .getComponent(ApiKeyService.class)
                    .getByApiAndMd5Key(ctx.getAttribute(ContextAttributes.ATTR_API), md5ApiKey);

                if (
                    this.handleApiKey(
                            apiKeyOpt,
                            ctx,
                            apiKey -> {
                                Callback[] callbacks = ctx.callbacks();
                                for (Callback callback : callbacks) {
                                    if (callback instanceof PlainAuthenticateCallback plainAuthenticateCallback) {
                                        plainAuthenticateCallback.authenticated(true);
                                        return true;
                                    } else if (callback instanceof ScramCredentialCallback scramCredentialCallback) {
                                        ScramCredential scramCredential = createScramCredential(
                                            apiKey.getKey(),
                                            ScramMechanism.forMechanismName(ctx.saslMechanism())
                                        );
                                        scramCredentialCallback.scramCredential(scramCredential);
                                        return true;
                                    }
                                }
                                return false;
                            }
                        )
                ) {
                    return Completable.complete();
                }
                return Completable.error(new Exception(API_KEY_INVALID_KEY));
            })
            .doOnTerminate(() -> cleanupApiKey(ctx));
    }

    private void cleanupApiKey(KafkaConnectionContext ctx) {
        ctx.removeInternalAttribute(ATTR_INTERNAL_MD5_API_KEY);
    }

    @SneakyThrows
    private ScramCredential createScramCredential(String password, ScramMechanism mechanism) {
        // Number of iterations for PBKDF2
        int iterations = 4096;

        // Generate a random salt (typically 16 bytes)
        byte[] salt = new byte[25];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);

        // ScramFormatter helps derive the storedKey and serverKey
        ScramFormatter formatter = new ScramFormatter(mechanism);

        // Generate storedKey and serverKey using the formatter
        return formatter.generateCredential(salt, formatter.saltedPassword(password, salt, iterations), iterations);
    }

    private boolean handleApiKey(Optional<ApiKey> apiKeyOpt, BaseExecutionContext ctx, Function<ApiKey, Boolean> handleIfApiKeyIsValid) {
        if (apiKeyOpt.isPresent()) {
            ApiKey apiKey = apiKeyOpt.get();

            // Add data about api-key, plan, application and subscription into the execution context.
            ctx.setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
            ctx.setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
            ctx.setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
            ctx.setAttribute(ATTR_API_KEY, apiKey.getKey());

            if (isApiKeyValid(ctx, apiKey)) {
                return handleIfApiKeyIsValid.apply(apiKey);
            }
        }
        return false;
    }
}
