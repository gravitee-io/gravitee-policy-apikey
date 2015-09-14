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
import io.gravitee.gateway.api.policy.annotations.OnRequest;
import io.gravitee.repository.api.ApiKeyRepository;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.model.ApiKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * @author David BRASSELY (brasseld at gmail.com)
 */
@SuppressWarnings("unused")
public class ApiKeyPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyPolicy.class);

    @OnRequest
    public void onRequest(Request request, Response response, PolicyContext policyContext, PolicyChain policyChain) {
        final String apiKeyHeader = request.headers().get(GraviteeHttpHeader.X_GRAVITEE_API_KEY.toString());

        LOGGER.debug("Looking for {} header from request {}", GraviteeHttpHeader.X_GRAVITEE_API_KEY.toString(), request.id());
        if (apiKeyHeader == null || apiKeyHeader.isEmpty()) {
            LOGGER.debug("No {} header value for request {}. Returning 401 status code.",
                    GraviteeHttpHeader.X_GRAVITEE_API_KEY.toString(), request.id());
            // The api key is required
            policyChain.sendError(HttpStatusCode.UNAUTHORIZED_401);
        } else {
            // Check if the api key exists and is valid
            try {
                final Optional<ApiKey> apiKeyOpt = policyContext.getComponent(ApiKeyRepository.class).retrieve(apiKeyHeader);
                if (apiKeyOpt.isPresent()) {
                    ApiKey apiKey = apiKeyOpt.get();
                    if (!apiKey.isRevoked() &&
                            ((apiKey.getExpiration() == null) || (apiKey.getExpiration().after(request.timestamp())))) {
                        LOGGER.debug("API Key for request {} has been validated.", request.id());

                        policyChain.doNext(request, response);
                    } else {
                        LOGGER.debug("API Key for request {} is invalid. Returning 403 status code.", request.id());

                        // The api key is not valid
                        policyChain.sendError(HttpStatusCode.FORBIDDEN_403);
                    }
                } else {
                    LOGGER.debug("API Key for request {} is invalid. Returning 403 status code.", request.id());
                    // The api key does not exist
                    policyChain.sendError(HttpStatusCode.FORBIDDEN_403);
                }
            } catch (TechnicalException te) {
                LOGGER.error("An unexpected error occurs while validation API Key. Returning 500 status code.", te);
                policyChain.sendError(HttpStatusCode.INTERNAL_SERVER_ERROR_500, te);
            }
        }
    }

}
