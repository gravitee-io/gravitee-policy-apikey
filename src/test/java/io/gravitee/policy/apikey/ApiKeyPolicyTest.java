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
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.gravitee.reporter.api.http.RequestMetrics;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.model.ApiKey;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static io.gravitee.common.http.GraviteeHttpHeader.X_GRAVITEE_API_KEY;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class ApiKeyPolicyTest {

    private static final String API_KEY_HEADER_VALUE = "fbc40d50-5746-40af-b283-d7e99c1775c7";

    private static final String API_NAME_HEADER_VALUE = "my-api";
    private static final String PLAN_NAME_HEADER_VALUE = "my-plan";

    private ApiKeyPolicy apiKeyPolicy;

    @Mock
    private ApiKeyPolicyConfiguration apiKeyPolicyConfiguration;

    @Mock
    private ApiKeyRepository apiKeyRepository;

    @Mock
    protected Request request;
    @Mock
    protected Response response;
    @Mock
    protected PolicyChain policyChain;
    @Mock
    protected ExecutionContext executionContext;

    @Before
    public void init() {
        initMocks(this);

        apiKeyPolicy = new ApiKeyPolicy(apiKeyPolicyConfiguration);
        when(request.metrics()).thenReturn(RequestMetrics.on(System.currentTimeMillis()).build());
    }

    @Test
    public void testOnRequest() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
            }
        });

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton(API_NAME_HEADER_VALUE));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findById(API_KEY_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequest_withUnexpiredKey() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
            }
        });
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpireAt(new Date());
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpireAt().toInstant().minus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton(API_NAME_HEADER_VALUE));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findById(API_KEY_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    @Ignore
    public void testOnRequest_withUnexpiredKeyAndBadApi() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
            }
        });
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpireAt(new Date());
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpireAt().toInstant().minus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton("bad-api"));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findById(API_KEY_HEADER_VALUE);
        verify(policyChain, times(0)).doNext(request, response);
    }

    @Test
    public void testOnRequest_withExpiredKey() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
            }
        });
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpireAt(new Date());
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpireAt().toInstant().plus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton(API_NAME_HEADER_VALUE));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findById(API_KEY_HEADER_VALUE);
        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestFailBecauseNoApiKey() {
        final HttpHeaders headers = new HttpHeaders();

        when(request.headers()).thenReturn(headers);

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestDoNotFailApiKeyOnHeader() throws TechnicalException {
        final HttpHeaders headers = new HttpHeaders();

        final Map<String, String> parameters = new HashMap<>();
        parameters.put(ApiKeyPolicy.API_KEY_QUERY_PARAMETER, API_KEY_HEADER_VALUE);

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(request.parameters()).thenReturn(parameters);

        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton(API_NAME_HEADER_VALUE));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findById(API_KEY_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequestFailBecauseApiKeyNotFoundOnRepository() throws TechnicalException {
        final String notExistingApiKey = "not_existing_api_key";
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, notExistingApiKey);
            }
        });

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));
        when(apiKeyRepository.findById(notExistingApiKey)).thenReturn(Optional.empty());
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton(API_NAME_HEADER_VALUE));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestFailBecauseApiKeyFoundButNotActive() throws TechnicalException{
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
            }
        });
        final ApiKey invalidApiKey = new ApiKey();
        invalidApiKey.setRevoked(true);


        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(invalidApiKey));
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton(API_NAME_HEADER_VALUE));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testApiKey_notPropagated() throws TechnicalException{
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
            }
        });

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton(API_NAME_HEADER_VALUE));
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        Assert.assertFalse(request.headers().containsKey(X_GRAVITEE_API_KEY));
        verify(apiKeyRepository).findById(API_KEY_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    @Ignore
    public void testApiKey_propagated() throws TechnicalException{
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
            }
        });

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findById(API_KEY_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));
        when(executionContext.getAttribute(ExecutionContext.ATTR_API + "-apis")).thenReturn(Collections.singleton(API_NAME_HEADER_VALUE));

        when(apiKeyPolicyConfiguration.isPropagateApiKey()).thenReturn(true);
        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        Assert.assertTrue(request.headers().containsKey(X_GRAVITEE_API_KEY));
        verify(apiKeyRepository).findById(API_KEY_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }
}