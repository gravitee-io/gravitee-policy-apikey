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


import io.gravitee.common.http.HttpHeaders;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyContext;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.reporter.api.metrics.Metrics;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.model.ApiKey;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static io.gravitee.common.http.GraviteeHttpHeader.X_GRAVITEE_API_KEY;
import static io.gravitee.common.http.GraviteeHttpHeader.X_GRAVITEE_API_NAME;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(MockitoJUnitRunner.class)
public class ApiKeyPolicyTest {

    private static final String API_KEY_HEADER_VALUE = "fbc40d50-5746-40af-b283-d7e99c1775c7";

    private static final String API_NAME_HEADER_VALUE = "my-api";

    @InjectMocks
    private ApiKeyPolicy apiKeyPolicy;

    @Mock
    private ApiKeyRepository apiKeyRepository;
    @Mock
    protected Request request;
    @Mock
    protected Response response;
    @Mock
    protected PolicyChain policyChain;
    @Mock
    protected PolicyContext policyContext;

    @Mock
    protected Metrics metrics;

    @Before
    public void init() {
        initMocks(this);

        when(response.metrics()).thenReturn(metrics);
    }

    @Test
    public void testOnRequest() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME, API_NAME_HEADER_VALUE);
            }
        });

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setApi(API_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(policyContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(apiKeyRepository.retrieve(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(apiKeyRepository).retrieve(API_KEY_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequest_withUnexpiredKey() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME, API_NAME_HEADER_VALUE);
            }
        });
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpiration(new Date());
        validApiKey.setApi(API_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpiration().toInstant().minus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate);
        when(policyContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(apiKeyRepository.retrieve(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(apiKeyRepository).retrieve(API_KEY_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequest_withUnexpiredKeyAndBadApi() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME, API_NAME_HEADER_VALUE);
            }
        });
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpiration(new Date());
        validApiKey.setApi("an-other-api");

        Instant requestDate = validApiKey.getExpiration().toInstant().minus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate);
        when(policyContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(apiKeyRepository.retrieve(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(apiKeyRepository).retrieve(API_KEY_HEADER_VALUE);
        verify(policyChain, times(0)).doNext(request, response);
    }

    @Test
    public void testOnRequest_withExpiredKey() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME, API_NAME_HEADER_VALUE);
            }
        });
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpiration(new Date());
        validApiKey.setApi(API_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpiration().toInstant().plus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate);
        when(policyContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(apiKeyRepository.retrieve(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(apiKeyRepository).retrieve(API_KEY_HEADER_VALUE);
        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestFailBecauseNoApiKey() {
        final HttpHeaders headers = new HttpHeaders();

        when(request.headers()).thenReturn(headers);

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestDoNotFailApiKeyOnHeader() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_NAME, API_NAME_HEADER_VALUE);
            }
        });

        final Map<String, String> parameters = new HashMap<>();
        parameters.put(ApiKeyPolicy.API_KEY_QUERY_PARAMETER, API_KEY_HEADER_VALUE);

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setApi(API_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(request.parameters()).thenReturn(parameters);

        when(policyContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(apiKeyRepository.retrieve(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(apiKeyRepository).retrieve(API_KEY_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequestFailBecauseApiKeyNotFoundOnRepository() throws TechnicalException {
        final String notExistingApiKey = "not_existing_api_key";
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, notExistingApiKey);
                put(X_GRAVITEE_API_NAME, API_NAME_HEADER_VALUE);
            }
        });

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);

        when(request.headers()).thenReturn(headers);
        when(policyContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(apiKeyRepository.retrieve(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));
        when(apiKeyRepository.retrieve(notExistingApiKey)).thenReturn(Optional.empty());

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestFailBecauseApiKeyFoundButNotActive() throws TechnicalException{
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME, API_NAME_HEADER_VALUE);
            }
        });
        final ApiKey invalidApiKey = new ApiKey();
        invalidApiKey.setRevoked(true);


        when(request.headers()).thenReturn(headers);
        when(policyContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(apiKeyRepository.retrieve(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(invalidApiKey));

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }
}