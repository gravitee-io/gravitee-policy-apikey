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

import static io.gravitee.common.http.GraviteeHttpHeader.X_GRAVITEE_API_KEY;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.model.ApiKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.env.Environment;

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
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain policyChain;

    @Mock
    private ExecutionContext executionContext;

    @Mock
    private Environment environment;

    @Before
    public void init() {
        initMocks(this);

        apiKeyPolicy = new ApiKeyPolicy(apiKeyPolicyConfiguration);
        ApiKeyPolicy.API_KEY_QUERY_PARAMETER = null;
        ApiKeyPolicy.API_KEY_HEADER = null;
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty(eq(ApiKeyPolicy.API_KEY_HEADER_PROPERTY), anyString()))
            .thenAnswer(invocation -> invocation.getArguments()[1]);
        when(environment.getProperty(eq(ApiKeyPolicy.API_KEY_QUERY_PARAMETER_PROPERTY), anyString()))
            .thenAnswer(invocation -> invocation.getArguments()[1]);
    }

    @Test
    public void testOnRequest() throws TechnicalException {
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void test_withNullConfiguration() throws TechnicalException {
        apiKeyPolicy = new ApiKeyPolicy(null);

        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequest_withUnexpiredKey() throws TechnicalException {
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpireAt(new Date());
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpireAt().toInstant().minus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate.toEpochMilli());
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequest_withCustomHeader() throws TechnicalException {
        final String customHeader = "My-Custom-Api-Key";
        when(environment.getProperty(eq(ApiKeyPolicy.API_KEY_HEADER_PROPERTY), anyString())).thenReturn(customHeader);

        final HttpHeaders headers = buildHttpHeaders(customHeader, API_KEY_HEADER_VALUE);
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpireAt(new Date());
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpireAt().toInstant().minus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate.toEpochMilli());
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequest_withCustomQueryParameter() throws TechnicalException {
        final String customQueryParameter = "my-api-key";
        when(environment.getProperty(eq(ApiKeyPolicy.API_KEY_QUERY_PARAMETER_PROPERTY), anyString())).thenReturn(customQueryParameter);

        final HttpHeaders headers = HttpHeaders.create();

        final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.put(customQueryParameter, Collections.singletonList(API_KEY_HEADER_VALUE));

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(request.parameters()).thenReturn(parameters);

        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    @Ignore
    public void testOnRequest_withUnexpiredKeyAndBadApi() throws TechnicalException {
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpireAt(new Date());
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpireAt().toInstant().minus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate.toEpochMilli());
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain, times(0)).doNext(request, response);
    }

    @Test
    public void testOnRequest_withExpiredKey() throws TechnicalException {
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setExpireAt(new Date());
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        Instant requestDate = validApiKey.getExpireAt().toInstant().plus(Duration.ofHours(1));

        when(request.headers()).thenReturn(headers);
        when(request.timestamp()).thenReturn(requestDate.toEpochMilli());
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestFailBecauseNoApiKey() {
        final HttpHeaders headers = HttpHeaders.create();

        when(request.headers()).thenReturn(headers);
        when(request.parameters()).thenReturn(mock(MultiValueMap.class));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestDoNotFailApiKeyOnHeader() throws TechnicalException {
        final HttpHeaders headers = HttpHeaders.create();

        final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.put(ApiKeyPolicy.DEFAULT_API_KEY_QUERY_PARAMETER, Collections.singletonList(API_KEY_HEADER_VALUE));

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(request.parameters()).thenReturn(parameters);

        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testOnRequestFailBecauseApiKeyNotFoundOnRepository() throws TechnicalException {
        final String notExistingApiKey = "not_existing_api_key";
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, notExistingApiKey);

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(notExistingApiKey, API_NAME_HEADER_VALUE)).thenReturn(Optional.empty());

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestFailBecauseApiKeyFoundButNotActive() throws TechnicalException {
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);
        final ApiKey invalidApiKey = new ApiKey();
        invalidApiKey.setRevoked(true);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(invalidApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(0)).doNext(request, response);
        verify(policyChain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testApiKey_notPropagatedBecauseNoConfig() throws TechnicalException {
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        (new ApiKeyPolicy(null)).onRequest(request, response, executionContext, policyChain);

        Assert.assertFalse(request.headers().contains(X_GRAVITEE_API_KEY));
        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testApiKey_notPropagatedBecauseItsAsked() throws TechnicalException {
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        Assert.assertFalse(request.headers().contains(X_GRAVITEE_API_KEY));
        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testApiKey_propagated() throws TechnicalException {
        final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY, API_KEY_HEADER_VALUE);

        final ApiKey validApiKey = new ApiKey();
        validApiKey.setRevoked(false);
        validApiKey.setPlan(PLAN_NAME_HEADER_VALUE);

        when(request.headers()).thenReturn(headers);
        when(executionContext.getComponent(ApiKeyRepository.class)).thenReturn(apiKeyRepository);
        when(executionContext.getAttribute(ExecutionContext.ATTR_API)).thenReturn(API_NAME_HEADER_VALUE);
        when(apiKeyRepository.findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE)).thenReturn(Optional.of(validApiKey));

        when(apiKeyPolicyConfiguration.isPropagateApiKey()).thenReturn(true);
        apiKeyPolicy.onRequest(request, response, executionContext, policyChain);

        Assert.assertTrue(request.headers().contains(X_GRAVITEE_API_KEY));
        verify(apiKeyRepository).findByKeyAndApi(API_KEY_HEADER_VALUE, API_NAME_HEADER_VALUE);
        verify(policyChain).doNext(request, response);
    }

    private HttpHeaders buildHttpHeaders(String headerKey, String headerValue) {
        return HttpHeaders.create().add(headerKey, headerValue);
    }
}
