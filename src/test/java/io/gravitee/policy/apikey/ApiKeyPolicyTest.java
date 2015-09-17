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


import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.policy.PolicyChain;
import io.gravitee.gateway.api.policy.PolicyContext;
import io.gravitee.gateway.api.policy.PolicyResult;
import io.gravitee.repository.api.ApiKeyRepository;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.model.ApiKey;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static io.gravitee.common.http.GraviteeHttpHeader.X_GRAVITEE_API_KEY;
import static io.gravitee.common.http.GraviteeHttpHeader.X_GRAVITEE_API_NAME;
import static java.util.Collections.emptyMap;
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

    @Before
    public void init() {
        initMocks(this);
    }

    @Test
    public void testOnRequest() throws TechnicalException {
        final Map<String, String> headers = new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY.toString(), API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME.toString(), API_NAME_HEADER_VALUE);
            }
        };
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
        final Map<String, String> headers = new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY.toString(), API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME.toString(), API_NAME_HEADER_VALUE);
            }
        };
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpiration(new Date());
        validApiKey.setApi(API_NAME_HEADER_VALUE);

        Date requestDate = Date.from(validApiKey.getExpiration().toInstant().minus(Duration.ofHours(1)));

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
        final Map<String, String> headers = new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY.toString(), API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME.toString(), API_NAME_HEADER_VALUE);
            }
        };
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpiration(new Date());
        validApiKey.setApi("an-other-api");

        Date requestDate = Date.from(validApiKey.getExpiration().toInstant().minus(Duration.ofHours(1)));

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
        final Map<String, String> headers = new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY.toString(), API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME.toString(), API_NAME_HEADER_VALUE);
            }
        };
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpiration(new Date());
        validApiKey.setApi(API_NAME_HEADER_VALUE);

        Date requestDate = Date.from(validApiKey.getExpiration().toInstant().plus(Duration.ofHours(1)));

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
    public void testOnRequestFailBecauseNoApiKeyOnHeader() {
        when(request.headers()).thenReturn(emptyMap());

        apiKeyPolicy.onRequest(request, response, policyContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestFailBecauseApiKeyNotFoundOnRepository() throws TechnicalException {
        final String notExistingApiKey = "not_existing_api_key";
        final Map<String, String> headers = new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY.toString(), notExistingApiKey);
                put(X_GRAVITEE_API_NAME.toString(), API_NAME_HEADER_VALUE);
            }
        };
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
        final Map<String, String> headers = new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY.toString(), API_KEY_HEADER_VALUE);
                put(X_GRAVITEE_API_NAME.toString(), API_NAME_HEADER_VALUE);
            }
        };
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