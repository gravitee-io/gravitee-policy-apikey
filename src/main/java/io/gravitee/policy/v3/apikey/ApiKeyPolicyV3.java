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
package io.gravitee.policy.v3.apikey;

import io.gravitee.common.http.GraviteeHttpHeader;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.service.ApiKey;
import io.gravitee.gateway.api.service.ApiKeyService;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import java.util.Date;
import java.util.Optional;
import org.springframework.core.env.Environment;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ApiKeyPolicyV3 {

    static final String ATTR_API_KEY = ExecutionContext.ATTR_PREFIX + "api-key";

    protected static final String API_KEY_MISSING_KEY = "API_KEY_MISSING";
    protected static final String API_KEY_INVALID_KEY = "API_KEY_INVALID";
    protected static final String API_KEY_INVALID_MESSAGE = "API Key is not valid or is expired / revoked.";

    /**
     * Policy configuration
     */
    private final ApiKeyPolicyConfiguration apiKeyPolicyConfiguration;

    private String apiKeyHeader, apiKeyQueryParameter;
    static final String API_KEY_HEADER_PROPERTY = "policy.api-key.header";
    static final String API_KEY_QUERY_PARAMETER_PROPERTY = "policy.api-key.param";
    static final String DEFAULT_API_KEY_QUERY_PARAMETER = "api-key";
    static final String DEFAULT_API_KEY_HEADER_PARAMETER = GraviteeHttpHeader.X_GRAVITEE_API_KEY;

    public ApiKeyPolicyV3(ApiKeyPolicyConfiguration apiKeyPolicyConfiguration) {
        this.apiKeyPolicyConfiguration = apiKeyPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String requestApiKey = lookForApiKey(executionContext, request);

        if (requestApiKey == null || requestApiKey.isEmpty()) {
            // The api key is required
            policyChain.failWith(
                PolicyResult.failure(
                    API_KEY_MISSING_KEY,
                    HttpStatusCode.UNAUTHORIZED_401,
                    "No API Key has been specified in headers (" + apiKeyHeader + ") or query parameters (" + apiKeyQueryParameter + ")."
                )
            );
        } else {
            final String apiId = (String) executionContext.getAttribute(ExecutionContext.ATTR_API);

            Optional<ApiKey> apiKeyOpt = executionContext.getComponent(ApiKeyService.class).getByApiAndKey(apiId, requestApiKey);

            // Always set the apikey into the context
            executionContext.setAttribute(ATTR_API_KEY, requestApiKey);

            if (apiKeyOpt.isPresent()) {
                ApiKey apiKey = apiKeyOpt.get();

                // Add data about api-key and subscription into the execution context
                executionContext.setAttribute(ExecutionContext.ATTR_APPLICATION, apiKey.getApplication());
                executionContext.setAttribute(ExecutionContext.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
                // Be sure to force the plan to the one linked to the apikey
                executionContext.setAttribute(ExecutionContext.ATTR_PLAN, apiKey.getPlan());

                if (!apiKey.isRevoked() && (apiKey.getExpireAt() == null || apiKey.getExpireAt().after(new Date(request.timestamp())))) {
                    policyChain.doNext(request, response);
                } else {
                    // The api key is not valid
                    policyChain.failWith(
                        PolicyResult.failure(API_KEY_INVALID_KEY, HttpStatusCode.UNAUTHORIZED_401, API_KEY_INVALID_MESSAGE)
                    );
                }
            } else {
                // The api key does not exist
                policyChain.failWith(PolicyResult.failure(API_KEY_INVALID_KEY, HttpStatusCode.UNAUTHORIZED_401, API_KEY_INVALID_MESSAGE));
            }
        }
    }

    private String lookForApiKey(ExecutionContext executionContext, Request request) {
        if (apiKeyHeader == null) {
            Environment environment = executionContext.getComponent(Environment.class);
            apiKeyHeader = environment.getProperty(API_KEY_HEADER_PROPERTY, DEFAULT_API_KEY_HEADER_PARAMETER);
            apiKeyQueryParameter = environment.getProperty(API_KEY_QUERY_PARAMETER_PROPERTY, DEFAULT_API_KEY_QUERY_PARAMETER);
        }

        // 1_ First, search in HTTP headers
        String apiKey = request.headers().getFirst(apiKeyHeader);
        if (apiKeyPolicyConfiguration == null || !apiKeyPolicyConfiguration.isPropagateApiKey()) {
            request.headers().remove(apiKeyHeader);
        }

        if (apiKey == null || apiKey.isEmpty()) {
            // 2_ If not found, search in query parameters
            apiKey = request.parameters().getFirst(apiKeyQueryParameter);

            if (apiKeyPolicyConfiguration == null || !apiKeyPolicyConfiguration.isPropagateApiKey()) {
                request.parameters().remove(apiKeyQueryParameter);
            }
        }

        return apiKey;
    }
}
