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
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.model.ApiKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Optional;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@SuppressWarnings("unused")
public class ApiKeyPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyPolicy.class);

    static final String API_KEY_QUERY_PARAMETER = "api-key";

    static final String ATTR_API_KEY = ExecutionContext.ATTR_PREFIX + "api-key";

    private final ApiKeyPolicyConfiguration apiKeyPolicyConfiguration;

    public ApiKeyPolicy(ApiKeyPolicyConfiguration apiKeyPolicyConfiguration) {
        this.apiKeyPolicyConfiguration = apiKeyPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String requestApiKey = lookForApiKey(request);

        if (requestApiKey == null || requestApiKey.isEmpty()) {
            // The api key is required
            policyChain.failWith(PolicyResult
                    .failure(HttpStatusCode.UNAUTHORIZED_401,
                            "No API Key has been specified in headers (" + GraviteeHttpHeader.X_GRAVITEE_API_KEY
                                    + ") or query parameters (" + API_KEY_QUERY_PARAMETER + ")."));
        } else {
            try {
                Optional<ApiKey> apiKeyOpt = executionContext.getComponent(ApiKeyRepository.class).findById(requestApiKey);

                // Set API Key in metrics even if the key is not valid, it's just to track calls with by API key
                request.metrics().setApiKey(requestApiKey);

                if (apiKeyOpt.isPresent()) {
                    ApiKey apiKey = apiKeyOpt.get();

                    // Add data about api-key and subscription into the execution context
                    executionContext.setAttribute(ExecutionContext.ATTR_APPLICATION, apiKey.getApplication());
                    executionContext.setAttribute(ExecutionContext.ATTR_USER_ID, apiKey.getSubscription());
                    executionContext.setAttribute(ExecutionContext.ATTR_PLAN, apiKey.getPlan());
                    executionContext.setAttribute(ATTR_API_KEY, apiKey.getKey());

                    final String apiName = (String) executionContext.getAttribute(ExecutionContext.ATTR_API);
//                    Optional<Plan> optPlan = executionContext.getComponent(PlanRepository.class).findById(apiKey.getPlan());

                    if (!apiKey.isRevoked() &&
                            ((apiKey.getExpireAt() == null) || (apiKey.getExpireAt().after(Date.from(request.timestamp()))))) {// &&
                            //(optPlan.get().getApis().contains(apiName))) {
                        policyChain.doNext(request, response);
                    } else {
                        // The api key is not valid
                        policyChain.failWith(
                                PolicyResult.failure(HttpStatusCode.FORBIDDEN_403,
                                        "API Key is not valid or is expired / revoked."));
                    }
                } else {
                    // The api key does not exist
                    policyChain.failWith(
                            PolicyResult.failure(HttpStatusCode.FORBIDDEN_403,
                                    "API Key is not valid or is expired / revoked."));
                }
            } catch (TechnicalException te) {
                LOGGER.error("An unexpected error occurs while validation API Key. Returning 500 status code.", te);
                policyChain.failWith(
                        PolicyResult.failure("API Key is not valid or is expired / revoked."));
            }
        }
    }

    private String lookForApiKey(Request request) {
        // 1_ First, search in HTTP headers
        String apiKey = request.headers().getFirst(GraviteeHttpHeader.X_GRAVITEE_API_KEY);
        request.headers().remove(GraviteeHttpHeader.X_GRAVITEE_API_KEY);

        if (apiKey == null || apiKey.isEmpty()) {
            // 2_ If not found, search in query parameters
            apiKey = request.parameters().getOrDefault(API_KEY_QUERY_PARAMETER, null);
            request.parameters().remove(API_KEY_QUERY_PARAMETER);
        }

        return apiKey;
    }
}
