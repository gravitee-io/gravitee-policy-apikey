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

import java.util.Optional;

import javax.annotation.Resource;

import io.gravitee.common.http.GraviteeHttpHeader;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.policy.PolicyChain;
import io.gravitee.gateway.api.policy.annotations.OnRequest;
import io.gravitee.repository.api.ApiKeyRepository;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.model.ApiKey;

@SuppressWarnings("unused")
public class ApiKeyPolicy {

    /** The associated configuration to this ApiKey Policy */
    private ApiKeyPolicyConfiguration configuration;

    @Resource
    private ApiKeyRepository apiKeyRepository;

    /**
     * Create a new ApiKey Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new ApiKey Policy instance
     */
    public ApiKeyPolicy(ApiKeyPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, PolicyChain policyChain) {
        final String apiKeyHeader = request.headers().get(GraviteeHttpHeader.X_GRAVITEE_API_KEY.name());
        if (apiKeyHeader == null || apiKeyHeader.isEmpty()) {
            // The api key is required
            policyChain.sendError(401);
        } else {
            // Check if the api key exists and is valid
            try {
                final Optional<ApiKey> apiKey = apiKeyRepository.retrieve(apiKeyHeader);
                if (apiKey.isPresent()) {
                    if (!apiKey.get().isRevoked()) {
                        policyChain.doNext(request, response);
                    } else {
                        // The api key is not valid
                        policyChain.sendError(403);
                    }
                } else {
                    // The api key does not exist
                    policyChain.sendError(403);
                }
            } catch (final TechnicalException e) {
                //TODO handle exceptions
            }
        }
    }

}
