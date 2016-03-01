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
 * @author David BRASSELY (brasseld at gmail.com)
 */
@SuppressWarnings("unused")
public class ApiKeyPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyPolicy.class);

    final static String API_KEY_QUERY_PARAMETER = "api-key";

    private final ApiKeyPolicyConfiguration apiKeyPolicyConfiguration;

    public ApiKeyPolicy(ApiKeyPolicyConfiguration apiKeyPolicyConfiguration) {
        this.apiKeyPolicyConfiguration = apiKeyPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String requestApiKey = lookForApiKey(request);

        if (requestApiKey == null || requestApiKey.isEmpty()) {
            LOGGER.debug("No API Key has been specified for request {}. Returning 401 status code.", request.id());

            // The api key is required
            policyChain.failWith(new PolicyResult() {
                @Override
                public boolean isFailure() {
                    return true;
                }

                @Override
                public int httpStatusCode() {
                    return HttpStatusCode.UNAUTHORIZED_401;
                }

                @Override
                public String message() {
                    return "No API Key has been specified in headers (" + GraviteeHttpHeader.X_GRAVITEE_API_KEY
                            + ") or query parameters (" + API_KEY_QUERY_PARAMETER + ").";
                }
            });
        } else {
            try {
                Optional<ApiKey> apiKeyOpt = executionContext.getComponent(ApiKeyRepository.class).retrieve(requestApiKey);

                // Set API Key in metrics even if the key is not valid, it's just to track calls with by API key
                request.metrics().setApiKey(requestApiKey);

                if (apiKeyOpt.isPresent()) {
                    ApiKey apiKey = apiKeyOpt.get();

                    executionContext.setAttribute(ExecutionContext.ATTR_APPLICATION, apiKey.getApplication());
                    executionContext.setAttribute(ExecutionContext.ATTR_API_KEY, apiKey.getKey());

                    request.metrics().setApplication(apiKey.getApplication());

                    final String apiName = (String) executionContext.getAttribute(ExecutionContext.ATTR_API);
                    if (!apiKey.isRevoked() &&
                            (apiKey.getApi().equalsIgnoreCase(apiName)) &&
                            ((apiKey.getExpiration() == null) || (apiKey.getExpiration().after(Date.from(request.timestamp()))))) {
                        LOGGER.debug("API Key for request {} has been validated.", request.id());

                        policyChain.doNext(request, response);
                    } else {
                        LOGGER.debug("API Key for request {} is invalid. Returning 403 status code.", request.id());

                        // The api key is not valid
                        policyChain.failWith(new PolicyResult() {
                            @Override
                            public boolean isFailure() {
                                return true;
                            }

                            @Override
                            public int httpStatusCode() {
                                return HttpStatusCode.FORBIDDEN_403;
                            }

                            @Override
                            public String message() {
                                return "API Key " + requestApiKey + " is not valid or is expired / revoked.";
                            }
                        });
                    }
                } else {
                    LOGGER.debug("API Key for request {} is invalid. Returning 403 status code.", request.id());
                    // The api key does not exist
                    policyChain.failWith(new PolicyResult() {
                        @Override
                        public boolean isFailure() {
                            return true;
                        }

                        @Override
                        public int httpStatusCode() {
                            return HttpStatusCode.FORBIDDEN_403;
                        }

                        @Override
                        public String message() {
                            return "API Key " + requestApiKey + " is not valid or is expired / revoked.";
                        }
                    });
                }
            } catch (TechnicalException te) {
                LOGGER.error("An unexpected error occurs while validation API Key. Returning 500 status code.", te);
                policyChain.failWith(new PolicyResult() {
                    @Override
                    public boolean isFailure() {
                        return true;
                    }

                    @Override
                    public int httpStatusCode() {
                        return HttpStatusCode.INTERNAL_SERVER_ERROR_500;
                    }

                    @Override
                    public String message() {
                        return "An unexpected error occurs while getting API Key from repository";
                    }
                });
            }
        }
    }

    private String lookForApiKey(Request request) {
        // 1_ First, search in HTTP headers
        String apiKey = request.headers().getFirst(GraviteeHttpHeader.X_GRAVITEE_API_KEY);

        LOGGER.debug("Looking for {} header from request {}", GraviteeHttpHeader.X_GRAVITEE_API_KEY, request.id());
        if (apiKey == null || apiKey.isEmpty()) {
            LOGGER.debug("No '{}' header value for request {}. Fallback to query param. Returning 401 status code.",
                    GraviteeHttpHeader.X_GRAVITEE_API_KEY, request.id());

            // 2_ If not found, search in query parameters
            apiKey = request.parameters().getOrDefault(API_KEY_QUERY_PARAMETER, null);
            LOGGER.debug("No '{}' parameter for request {}. Returning empty API Key", API_KEY_QUERY_PARAMETER, request.id());
        }

        if (! apiKeyPolicyConfiguration.isPropagateApiKey()) {
            request.headers().remove(GraviteeHttpHeader.X_GRAVITEE_API_KEY);
            request.parameters().remove(API_KEY_QUERY_PARAMETER);
        }

        return apiKey;
    }
}
