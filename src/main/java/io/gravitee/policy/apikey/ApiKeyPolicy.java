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
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.policy.PolicyChain;
import io.gravitee.gateway.api.policy.PolicyContext;
import io.gravitee.gateway.api.policy.PolicyResult;
import io.gravitee.gateway.api.policy.annotations.OnRequest;
import io.gravitee.policy.apikey.configuration.ApiKey;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.gravitee.repository.api.management.ApiKeyRepository;
import io.gravitee.repository.exceptions.TechnicalException;
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

    /**
     * The associated configuration to this API Key Policy
     */
    private ApiKeyPolicyConfiguration configuration;

    /**
     * Create a new API Key Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the API Key Policy instance
     */
    public ApiKeyPolicy(ApiKeyPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, PolicyContext policyContext, PolicyChain policyChain) {
        final String apiName = request.headers().getFirst(GraviteeHttpHeader.X_GRAVITEE_API_NAME);

        final String apiKeyHeader = request.headers().getFirst(GraviteeHttpHeader.X_GRAVITEE_API_KEY);

        LOGGER.debug("Looking for {} header from request {}", GraviteeHttpHeader.X_GRAVITEE_API_KEY, request.id());
        if (apiKeyHeader == null || apiKeyHeader.isEmpty()) {
            LOGGER.debug("No {} header value for request {}. Returning 401 status code.",
                    GraviteeHttpHeader.X_GRAVITEE_API_KEY, request.id());
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
                    return "An HTTP header value must be specified for " + GraviteeHttpHeader.X_GRAVITEE_API_KEY;
                }
            });
        } else {
            Optional<ApiKey> apiKeyOpt = Optional.empty();

            // Check if the api key exists and is valid
            if (configuration != null && ! configuration.getKeys().isEmpty()) {
                apiKeyOpt = configuration.getKeys().stream()
                        .filter(apiKey -> apiKey.getKey().equals(apiKeyHeader))
                        .findFirst();
            } else {
                try {
                    apiKeyOpt = Optional.ofNullable(convert(policyContext.getComponent(ApiKeyRepository.class).retrieve(apiKeyHeader)));
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

            if (apiKeyOpt.isPresent()) {
                ApiKey apiKey = apiKeyOpt.get();
                if (!apiKey.isRevoked() &&
                        ((apiKey.isApiScoped()) || (apiKey.getApi().equalsIgnoreCase(apiName)))   &&
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
                            return "API Key " + apiKeyHeader + " is not valid or is expired / revoked.";
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
                        return "API Key " + apiKeyHeader + " is not valid or is expired / revoked.";
                    }
                });
            }
        }
    }

    private ApiKey convert(Optional<io.gravitee.repository.model.management.ApiKey> apiKeyRepo) {
        if (! apiKeyRepo.isPresent())  {
            return null;
        }

        ApiKey key = new ApiKey();

        key.setKey(apiKeyRepo.get().getKey());
        key.setRevoked(apiKeyRepo.get().isRevoked());
        key.setExpiration(apiKeyRepo.get().getExpiration());
        key.setApi(apiKeyRepo.get().getApi());
        key.setApiScoped(false);

        return key;
    }
}
