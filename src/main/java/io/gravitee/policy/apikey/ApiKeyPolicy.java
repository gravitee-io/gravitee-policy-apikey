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
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.gravitee.policy.apikey.configuration.ErrorType;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.model.ApiKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import java.util.Date;
import java.util.Optional;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@SuppressWarnings("unused")
public class ApiKeyPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyPolicy.class);

    static final String ATTR_API_KEY = ExecutionContext.ATTR_PREFIX + "api-key";

    /**
     * Policy configuration
     */
    private final ApiKeyPolicyConfiguration apiKeyPolicyConfiguration;

    static String API_KEY_HEADER, API_KEY_QUERY_PARAMETER;
    static final String API_KEY_HEADER_PROPERTY = "policy.api-key.header";
    static final String API_KEY_QUERY_PARAMETER_PROPERTY = "policy.api-key.param";
    static final String DEFAULT_API_KEY_QUERY_PARAMETER = "api-key";
    static final String DEFAULT_API_KEY_HEADER_PARAMETER = GraviteeHttpHeader.X_GRAVITEE_API_KEY;

    public ApiKeyPolicy(ApiKeyPolicyConfiguration apiKeyPolicyConfiguration) {
        this.apiKeyPolicyConfiguration = apiKeyPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        final String accept = request.headers().getFirst("Accept");
        String requestApiKey = lookForApiKey(executionContext, request);

        if (requestApiKey == null || requestApiKey.isEmpty()) {
            // The api key is required
            policyChain.failWith(this.getPolicyResult(accept, ErrorType.MISSING));
        } else {
            try {
                final Optional<ApiKey> apiKeyOpt = executionContext.getComponent(ApiKeyRepository.class).findById(requestApiKey);

                // Set API Key in metrics even if the key is not valid, it's just to track calls with by API key
                request.metrics().setApiKey(requestApiKey);

                if (apiKeyOpt.isPresent()) {
                    ApiKey apiKey = apiKeyOpt.get();

                    // Add data about api-key and subscription into the execution context
                    executionContext.setAttribute(ExecutionContext.ATTR_APPLICATION, apiKey.getApplication());
                    executionContext.setAttribute(ExecutionContext.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
                    // Be sure to force the plan to the one linked to the apikey
                    executionContext.setAttribute(ExecutionContext.ATTR_PLAN, apiKey.getPlan());
                    executionContext.setAttribute(ATTR_API_KEY, apiKey.getKey());

                    final String apiId = (String) executionContext.getAttribute(ExecutionContext.ATTR_API);

                    if (!apiKey.isRevoked()
                            && (apiKey.getExpireAt() == null || apiKey.getExpireAt().after(new Date(request.timestamp())))) {
                        policyChain.doNext(request, response);
                    } else {
                        // The api key is not valid
                        policyChain.failWith(this.getPolicyResult(accept, ErrorType.WRONG_EXPIRED_REVOKED));
                    }
                } else {
                    // The api key does not exist
                    policyChain.failWith(this.getPolicyResult(accept, ErrorType.WRONG_EXPIRED_REVOKED));
                }
            } catch (final TechnicalException te) {
                ApiKeyPolicy.LOGGER.error("An unexpected error occurs while validation API Key. Returning 500 status code.", te);
                policyChain.failWith(this.getPolicyResult(accept, ErrorType.WRONG_EXPIRED_REVOKED));
            }
        }
    }

    private String lookForApiKey(ExecutionContext executionContext, Request request) {
        if (API_KEY_HEADER == null) {
            Environment environment = executionContext.getComponent(Environment.class);
            API_KEY_HEADER = environment.getProperty(API_KEY_HEADER_PROPERTY, DEFAULT_API_KEY_HEADER_PARAMETER);
            API_KEY_QUERY_PARAMETER = environment.getProperty(API_KEY_QUERY_PARAMETER_PROPERTY, DEFAULT_API_KEY_QUERY_PARAMETER);
        }

        // 1_ First, search in HTTP headers
        String apiKey = request.headers().getFirst(API_KEY_HEADER);
        if (apiKeyPolicyConfiguration == null || ! apiKeyPolicyConfiguration.isPropagateApiKey()) {
            request.headers().remove(API_KEY_HEADER);
        }

        if (apiKey == null || apiKey.isEmpty()) {
            // 2_ If not found, search in query parameters
            apiKey = request.parameters().getFirst(API_KEY_QUERY_PARAMETER);

            if (apiKeyPolicyConfiguration == null || ! apiKeyPolicyConfiguration.isPropagateApiKey()) {
                request.parameters().remove(API_KEY_QUERY_PARAMETER);
            }
        }

        return apiKey;
    }

    /**
     * determine the {@link PolicyResult} to be send back. The given <code>Accept</code> header value and {@link ErrorType error type} is used
     * to find a matching {@link io.gravitee.policy.apikey.configuration.Response response} configuration. If not found the default and backward
     * compatible {@link PolicyResult} is used.
     *
     * @param accept
     *        content of the <code>Accept</code> header param, may ne <code>null</code>.
     * @param errorType
     *        the {@link ErrorType} to create an {@link PolicyResult} for, not <code>null</code>.
     * @return a {@link PolicyResult} for the given <code>Accept</code> header value and {@link ErrorType error type}, not <code>null</code>.
     * @since 1.6.3
     */
    private PolicyResult getPolicyResult(final String accept, final ErrorType errorType) {
        if (this.apiKeyPolicyConfiguration.getResponses() != null) {
            final Optional<io.gravitee.policy.apikey.configuration.Response> optionalResponse =
                    this.apiKeyPolicyConfiguration.getResponses().stream().filter(
                            response -> response.getContentType().equalsIgnoreCase(accept) && response.getType().equals(errorType)).findFirst();
            if (optionalResponse.isPresent()) {
                final io.gravitee.policy.apikey.configuration.Response response = optionalResponse.get();
                return PolicyResult.failure(response.getStatusCode(), response.getContent(), accept);
            }
        }

        // no matching response found, using defaults for backward compatibility:
        switch (errorType) {
            case MISSING:
                return PolicyResult.failure(
                        HttpStatusCode.UNAUTHORIZED_401,
                        "No API Key has been specified in headers (" + ApiKeyPolicy.API_KEY_HEADER + ") or query parameters ("
                                + ApiKeyPolicy.API_KEY_QUERY_PARAMETER + ").");
            case WRONG_EXPIRED_REVOKED:
                //$FALL-THROUGH$
            default:
                return PolicyResult.failure(HttpStatusCode.FORBIDDEN_403, "API Key is not valid or is expired / revoked.");
        }
    }
}
