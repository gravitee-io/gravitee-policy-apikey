/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.apikey;

import static io.gravitee.common.http.GraviteeHttpHeader.X_GRAVITEE_API_KEY;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_API;
import static io.gravitee.gateway.reactive.api.context.InternalContextAttributes.ATTR_INTERNAL_SECURITY_TOKEN;
import static io.gravitee.policy.apikey.ApiKeyPolicy.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.api.service.ApiKey;
import io.gravitee.gateway.api.service.ApiKeyService;
import io.gravitee.gateway.reactive.api.context.ContextAttributes;
import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.gateway.reactive.api.context.Request;
import io.gravitee.gateway.reactive.api.context.Response;
import io.gravitee.gateway.reactive.api.context.kafka.KafkaConnectionContext;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.observers.TestObserver;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.apache.kafka.common.security.scram.ScramCredentialCallback;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.util.DigestUtils;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
public class ApiKeyPolicyTest {

    private static final String API_KEY = "fbc40d50-5746-40af-b283-d7e99c1775c7";
    private static final String API_KEY_MD5 = DigestUtils.md5DigestAsHex(API_KEY.getBytes());
    private static final String CUSTOM_API_KEY = "username:password";

    private static final String API_ID = "apiId";
    private static final String PLAN_ID = "planId";
    protected static final String APPLICATION_ID = "applicationId";
    protected static final String SUBSCRIPTION_ID = "subscriptionId";
    protected static final Date EXPIRE_AT = new Date(System.currentTimeMillis() + 3600000);
    protected static final RuntimeException MOCK_EXCEPTION = new RuntimeException("Mock exception");

    @Mock
    private ApiKeyPolicyConfiguration configuration;

    @Mock
    private ApiKeyService apiKeyService;

    @Nested
    class HttpPolicy {

        @Mock
        private Request request;

        @Mock
        private Response response;

        @Mock
        private HttpExecutionContext ctx;

        @Mock
        private Environment environment;

        @BeforeEach
        void init() {
            ApiKeyPolicy.API_KEY_QUERY_PARAMETER = null;
            ApiKeyPolicy.API_KEY_HEADER = null;

            lenient().when(ctx.request()).thenReturn(request);
            lenient().when(ctx.timestamp()).thenReturn(System.currentTimeMillis());

            // Initialize default header and query param names to get API Key from.
            initializeParamNames(DEFAULT_API_KEY_HEADER_PARAMETER, DEFAULT_API_KEY_QUERY_PARAMETER);
        }

        @Test
        void shouldCompleteWhenApiKeyIsValid() {
            final HttpHeaders headers = buildHttpHeaders(DEFAULT_API_KEY_HEADER_PARAMETER);
            final ApiKey apiKey = buildApiKey();

            when(configuration.isPropagateApiKey()).thenReturn(true);
            when(request.headers()).thenReturn(headers);
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            verify(ctx).setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
            verify(ctx).setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
            verify(ctx).setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
            verify(ctx).setAttribute(ATTR_API_KEY, apiKey.getKey());

            assertEquals(API_KEY, headers.get(X_GRAVITEE_API_KEY));
        }

        @Test
        void shouldCompleteWhenApiKeyAlreadyInContextInternalAttributes() {
            final ApiKey apiKey = buildApiKey();

            when(configuration.isPropagateApiKey()).thenReturn(true);
            when(ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY)).thenReturn(API_KEY);
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();
        }

        @Test
        void shouldCompleteAndRemoveApiKeyFromInternalAttributeWhenConfigurationIsNull() {
            final ApiKey apiKey = buildApiKey();

            when(ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY)).thenReturn(API_KEY);
            when(request.headers()).thenReturn(mock(HttpHeaders.class));
            when(request.parameters()).thenReturn(mock(MultiValueMap.class));

            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(null);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            verify(ctx).removeInternalAttribute(ATTR_INTERNAL_API_KEY);
        }

        @Test
        void shouldCompleteAndRemoveApiKeyFromInternalAttributeWhenPropagateApiKeyIsDisabled() {
            final ApiKey apiKey = buildApiKey();

            when(configuration.isPropagateApiKey()).thenReturn(false);
            when(ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY)).thenReturn(API_KEY);
            when(request.headers()).thenReturn(mock(HttpHeaders.class));
            when(request.parameters()).thenReturn(mock(MultiValueMap.class));
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            verify(ctx).removeInternalAttribute(ATTR_INTERNAL_API_KEY);
        }

        @Test
        void shouldCompleteAndRemoveApiKeyFromHeaderWhenPropagateApiKeyIsDisabled() {
            final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY);
            final ApiKey apiKey = buildApiKey();

            when(configuration.isPropagateApiKey()).thenReturn(false);
            when(request.headers()).thenReturn(headers);
            when(request.parameters()).thenReturn(mock(MultiValueMap.class));
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            assertFalse(headers.contains(X_GRAVITEE_API_KEY));
        }

        @Test
        void shouldCompleteWhenCustomHeader() {
            final String customHeader = "My-Custom-Api-Key";

            final HttpHeaders headers = buildHttpHeaders(customHeader);
            final ApiKey apiKey = buildApiKey();

            initializeParamNames(customHeader, DEFAULT_API_KEY_QUERY_PARAMETER);
            when(configuration.isPropagateApiKey()).thenReturn(true);
            when(request.headers()).thenReturn(headers);
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            assertTrue(headers.contains(customHeader));
        }

        @Test
        void shouldCompleteAndRemoveApiKeyFromCustomHeaderWhenPropagateApiKeyIsDisabled() {
            final String customHeader = "My-Custom-Api-Key";

            final HttpHeaders headers = buildHttpHeaders(customHeader);
            final ApiKey apiKey = buildApiKey();

            initializeParamNames(customHeader, DEFAULT_API_KEY_QUERY_PARAMETER);
            when(configuration.isPropagateApiKey()).thenReturn(false);
            when(request.headers()).thenReturn(headers);
            when(request.parameters()).thenReturn(mock(MultiValueMap.class));
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            assertFalse(headers.contains(customHeader));
        }

        @Test
        void shouldCompleteAndRemoveApiKeyFromQueryParamWhenPropagateApiKeyIsDisabled() {
            final ApiKey apiKey = buildApiKey();
            final MultiValueMap<String, String> parameters = buildQueryParameters(DEFAULT_API_KEY_QUERY_PARAMETER);

            when(request.parameters()).thenReturn(parameters);
            when(configuration.isPropagateApiKey()).thenReturn(false);
            when(request.headers()).thenReturn(HttpHeaders.create());
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            assertFalse(request.parameters().containsKey(DEFAULT_API_KEY_QUERY_PARAMETER));
        }

        @Test
        void shouldCompleteWhenCustomQueryParam() {
            final ApiKey apiKey = buildApiKey();
            final String customQueryParam = "My-Custom-Api-Key";
            final MultiValueMap<String, String> parameters = buildQueryParameters(customQueryParam);

            initializeParamNames(DEFAULT_API_KEY_HEADER_PARAMETER, customQueryParam);
            when(request.parameters()).thenReturn(parameters);
            when(configuration.isPropagateApiKey()).thenReturn(true);
            when(request.headers()).thenReturn(HttpHeaders.create());
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            assertTrue(request.parameters().containsKey(customQueryParam));
        }

        @Test
        void shouldCompleteAndRemoveApiKeyFromCustomQueryParamWhenPropagateApiKeyIsDisabled() {
            final ApiKey apiKey = buildApiKey();
            final String customQueryParam = "My-Custom-Api-Key";
            final MultiValueMap<String, String> parameters = buildQueryParameters(customQueryParam);

            initializeParamNames(DEFAULT_API_KEY_HEADER_PARAMETER, customQueryParam);
            when(request.parameters()).thenReturn(parameters);
            when(configuration.isPropagateApiKey()).thenReturn(false);
            when(request.headers()).thenReturn(mock(HttpHeaders.class));
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertResult();

            assertFalse(request.parameters().containsKey(customQueryParam));
        }

        @Test
        void shouldInterruptWith401WhenNoApiKey() {
            when(request.parameters()).thenReturn(new LinkedMultiValueMap<>());
            when(request.headers()).thenReturn(HttpHeaders.create());
            when(ctx.interruptWith(any())).thenReturn(Completable.error(MOCK_EXCEPTION));

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertFailure(Throwable.class);

            verify(ctx)
                .interruptWith(
                    argThat(failure -> {
                        assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                        assertEquals("Unauthorized", failure.message());
                        assertEquals("API_KEY_MISSING", failure.key());
                        assertNull(failure.parameters());
                        assertNull(failure.contentType());

                        return true;
                    })
                );
        }

        @Test
        void shouldInterruptWith401WhenApiKeyExpired() {
            final ApiKey apiKey = buildApiKey();
            apiKey.setExpireAt(new Date(System.currentTimeMillis() - 3600000));

            when(configuration.isPropagateApiKey()).thenReturn(true);
            when(ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY)).thenReturn(API_KEY);
            mockApiKeyService(apiKey);
            when(ctx.interruptWith(any())).thenReturn(Completable.error(MOCK_EXCEPTION));

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertFailure(Throwable.class);

            verify(ctx)
                .interruptWith(
                    argThat(failure -> {
                        assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                        assertEquals("Unauthorized", failure.message());
                        assertEquals("API_KEY_INVALID", failure.key());
                        assertNull(failure.parameters());
                        assertNull(failure.contentType());

                        return true;
                    })
                );
        }

        @Test
        void shouldInterruptWith401WhenApiKeyRevoked() {
            final ApiKey apiKey = buildApiKey();
            apiKey.setRevoked(true);

            when(configuration.isPropagateApiKey()).thenReturn(true);
            when(ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY)).thenReturn(API_KEY);
            mockApiKeyService(apiKey);
            when(ctx.interruptWith(any())).thenReturn(Completable.error(MOCK_EXCEPTION));

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertFailure(Throwable.class);

            verify(ctx)
                .interruptWith(
                    argThat(failure -> {
                        assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                        assertEquals("Unauthorized", failure.message());
                        assertEquals("API_KEY_INVALID", failure.key());
                        assertNull(failure.parameters());
                        assertNull(failure.contentType());

                        return true;
                    })
                );
        }

        @Test
        void shouldInterruptWith401WhenApiKeyNotFound() {
            final HttpHeaders headers = buildHttpHeaders(DEFAULT_API_KEY_HEADER_PARAMETER);

            when(configuration.isPropagateApiKey()).thenReturn(true);
            when(request.headers()).thenReturn(headers);
            mockApiKeyService(null);
            when(ctx.interruptWith(any())).thenReturn(Completable.error(MOCK_EXCEPTION));

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertFailure(Throwable.class);

            verify(ctx)
                .interruptWith(
                    argThat(failure -> {
                        assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                        assertEquals("Unauthorized", failure.message());
                        assertEquals("API_KEY_INVALID", failure.key());
                        assertNull(failure.parameters());
                        assertNull(failure.contentType());

                        return true;
                    })
                );
        }

        @Test
        void shouldInterruptWith401WhenExceptionOccurred() {
            when(configuration.isPropagateApiKey()).thenReturn(true);
            when(request.headers()).thenThrow(MOCK_EXCEPTION);
            when(ctx.interruptWith(any())).thenReturn(Completable.error(MOCK_EXCEPTION));

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.onRequest(ctx).test();

            obs.assertFailure(Throwable.class);

            verify(ctx)
                .interruptWith(
                    argThat(failure -> {
                        assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                        assertEquals("Unauthorized", failure.message());
                        assertEquals("API_KEY_INVALID", failure.key());
                        assertNull(failure.parameters());
                        assertNull(failure.contentType());

                        return true;
                    })
                );
        }

        @Test
        void extractSecurityToken_shouldReturnSecurityToken_whenApiKeyInternalAttributeIsFound() {
            when(ctx.getInternalAttribute(ATTR_INTERNAL_API_KEY)).thenReturn(API_KEY);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertValue(token ->
                token.getTokenType().equals(SecurityToken.TokenType.API_KEY.name()) && token.getTokenValue().equals(API_KEY)
            );
        }

        @Test
        void extractSecurityToken_shouldReturnSecurityToken_whenApiKeyHeaderIsFound() {
            final HttpHeaders headers = buildHttpHeaders(X_GRAVITEE_API_KEY);
            when(request.headers()).thenReturn(headers);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertValue(token ->
                token.getTokenType().equals(SecurityToken.TokenType.API_KEY.name()) && token.getTokenValue().equals(API_KEY)
            );
        }

        @Test
        void extractSecurityToken_shouldReturnSecurityToken_whenApiKeyQueryParamIsFound() {
            final MultiValueMap<String, String> parameters = buildQueryParameters(DEFAULT_API_KEY_QUERY_PARAMETER);
            when(request.headers()).thenReturn(HttpHeaders.create());
            when(request.parameters()).thenReturn(parameters);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertValue(token ->
                token.getTokenType().equals(SecurityToken.TokenType.API_KEY.name()) && token.getTokenValue().equals(API_KEY)
            );
        }

        @Test
        void extractSecurityToken_shouldReturnEmpty_whenNoApiKeyIsFound() {
            when(request.headers()).thenReturn(HttpHeaders.create());
            when(request.parameters()).thenReturn(new LinkedMultiValueMap<>());

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertComplete().assertValueCount(0);
        }

        @Test
        void shouldNotValidateSubscription() {
            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            assertTrue(cut.requireSubscription());
        }

        @Test
        void shouldReturnIdApiKey() {
            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            assertEquals("api-key", cut.id());
        }

        @Test
        void shouldReturnOrder500() {
            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            assertEquals(500, cut.order());
        }

        private HttpHeaders buildHttpHeaders(String headerKey) {
            return HttpHeaders.create().add(headerKey, ApiKeyPolicyTest.API_KEY);
        }

        private MultiValueMap<String, String> buildQueryParameters(String paramKey) {
            final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.put(paramKey, List.of(ApiKeyPolicyTest.API_KEY));
            return parameters;
        }

        private void mockApiKeyService(ApiKey apiKey) {
            when(ctx.getComponent(ApiKeyService.class)).thenReturn(apiKeyService);
            when(ctx.getAttribute(ATTR_API)).thenReturn(API_ID);
            when(apiKeyService.getByApiAndKey(API_ID, API_KEY)).thenReturn(Optional.ofNullable(apiKey));
        }

        private void initializeParamNames(String apiKeyHeaderName, String apiKeyQueryParameterName) {
            ApiKeyPolicy.API_KEY_HEADER = apiKeyHeaderName;
            ApiKeyPolicy.API_KEY_QUERY_PARAMETER = apiKeyQueryParameterName;
        }
    }

    @Nested
    class KafkaPolicy {

        @Mock
        private KafkaConnectionContext ctx;

        @Mock
        private Environment environment;

        @BeforeEach
        void init() {
            lenient().when(ctx.timestamp()).thenReturn(System.currentTimeMillis());
        }

        @Test
        void extractSecurityToken_shouldReturnMD5SecurityToken_whenScram() {
            NameCallback nameCallback = new NameCallback("prompt", "default name");
            nameCallback.setName(API_KEY_MD5);

            ScramCredentialCallback scramCredentialCallback = new ScramCredentialCallback();

            when(ctx.callbacks()).thenReturn(new Callback[] { nameCallback, scramCredentialCallback });

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertValue(token ->
                token.getTokenType().equals(SecurityToken.TokenType.MD5_API_KEY.name()) && token.getTokenValue().equals(API_KEY_MD5)
            );
        }

        void extractSecurityToken_shouldReturnNonMD5SecurityToken_whenCustomApikey() {
            NameCallback nameCallback = new NameCallback("prompt", "default name");
            nameCallback.setName("username");

            PlainAuthenticateCallback plainAuthenticateCallback = new PlainAuthenticateCallback("password".toCharArray());

            when(ctx.callbacks()).thenReturn(new Callback[] { nameCallback, plainAuthenticateCallback });

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertValue(token ->
                token.getTokenType().equals(SecurityToken.TokenType.API_KEY.name()) && token.getTokenValue().equals(CUSTOM_API_KEY)
            );
        }

        @Test
        void extractSecurityToken_shouldReturnMD5SecurityToken_whenPlain() {
            NameCallback nameCallback = new NameCallback("prompt", "default name");
            nameCallback.setName(API_KEY_MD5);

            PlainAuthenticateCallback plainAuthenticateCallback = new PlainAuthenticateCallback(API_KEY.toCharArray());

            when(ctx.callbacks()).thenReturn(new Callback[] { nameCallback, plainAuthenticateCallback });

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertValue(token ->
                token.getTokenType().equals(SecurityToken.TokenType.MD5_API_KEY.name()) && token.getTokenValue().equals(API_KEY_MD5)
            );
        }

        @Test
        void extractSecurityToken_shouldReturnNonSecurityToken_whenCallbackHasDefaultName() {
            NameCallback nameCallback = new NameCallback("prompt", "default name");
            PlainAuthenticateCallback plainAuthenticateCallback = new PlainAuthenticateCallback("password".toCharArray());

            when(ctx.callbacks()).thenReturn(new Callback[] { nameCallback, plainAuthenticateCallback });

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertValue(token ->
                token.getTokenType().equals(SecurityToken.TokenType.API_KEY.name()) && token.getTokenValue().equals("default name:password")
            );
        }

        @Test
        void extractSecurityToken_shouldReturnEmpty_whenNoNameCallback() {
            when(ctx.callbacks()).thenReturn(new Callback[] {});

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertNoValues();
            verify(ctx, never()).setInternalAttribute(any(), any());
        }

        @Test
        void extractSecurityToken_shouldReturnInvalidSecurityToken_whenCallbackIsEmpty() {
            NameCallback nameCallback = new NameCallback("prompt");

            when(ctx.callbacks()).thenReturn(new Callback[] { nameCallback });

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

            obs.assertValue(token -> token.getTokenType().equals(SecurityToken.TokenType.MD5_API_KEY.name()) && token.isInvalid());
            verify(ctx, never()).setInternalAttribute(any(), any());
        }

        @Test
        void authenticate_shouldCompleteWhenApiKeyIsValid_whenCustomApikey() {
            PlainAuthenticateCallback plainAuthenticateCallback = new PlainAuthenticateCallback("password".toCharArray());
            when(ctx.callbacks()).thenReturn(new Callback[] { plainAuthenticateCallback });

            when(ctx.getInternalAttribute(ATTR_INTERNAL_SECURITY_TOKEN))
                .thenReturn(SecurityToken.builder().tokenType(SecurityToken.TokenType.API_KEY.name()).tokenValue(CUSTOM_API_KEY).build());

            final ApiKey apiKey = buildApiKey(CUSTOM_API_KEY);
            when(ctx.getComponent(ApiKeyService.class)).thenReturn(apiKeyService);
            when(ctx.getAttribute(ATTR_API)).thenReturn(API_ID);
            when(apiKeyService.getByApiAndKey(API_ID, CUSTOM_API_KEY)).thenReturn(Optional.of(apiKey));

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.authenticate(ctx).test();

            obs.assertComplete();
            assertThat(plainAuthenticateCallback.authenticated()).isTrue();

            verify(ctx).setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
            verify(ctx).setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
            verify(ctx).setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
            verify(ctx).setAttribute(ATTR_API_KEY, apiKey.getKey());
        }

        @Test
        void authenticate_shouldCompleteWhenApiKeyIsValid_whenPlain() {
            PlainAuthenticateCallback plainAuthenticateCallback = new PlainAuthenticateCallback(API_KEY.toCharArray());
            when(ctx.callbacks()).thenReturn(new Callback[] { plainAuthenticateCallback });

            when(ctx.getInternalAttribute(ATTR_INTERNAL_SECURITY_TOKEN))
                .thenReturn(SecurityToken.builder().tokenType(SecurityToken.TokenType.MD5_API_KEY.name()).tokenValue(API_KEY_MD5).build());

            final ApiKey apiKey = buildApiKey();
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.authenticate(ctx).test();

            obs.assertComplete();
            assertThat(plainAuthenticateCallback.authenticated()).isTrue();

            verify(ctx).setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
            verify(ctx).setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
            verify(ctx).setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
            verify(ctx).setAttribute(ATTR_API_KEY, apiKey.getKey());
        }

        @Test
        void authenticate_shouldCompleteWhenApiKeyIsValid_whenScram() {
            ScramCredentialCallback scramCredentialCallback = new ScramCredentialCallback();
            when(ctx.callbacks()).thenReturn(new Callback[] { scramCredentialCallback });

            when(ctx.saslMechanism()).thenReturn("SCRAM-SHA-256");
            when(ctx.getInternalAttribute(ATTR_INTERNAL_SECURITY_TOKEN))
                .thenReturn(SecurityToken.builder().tokenType(SecurityToken.TokenType.MD5_API_KEY.name()).tokenValue(API_KEY_MD5).build());

            final ApiKey apiKey = buildApiKey();
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.authenticate(ctx).test();

            obs.assertComplete();
            assertThat(scramCredentialCallback.scramCredential()).isNotNull();

            verify(ctx).setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
            verify(ctx).setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
            verify(ctx).setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
            verify(ctx).setAttribute(ATTR_API_KEY, apiKey.getKey());
        }

        @Test
        void authenticate_shouldNotCompleteWhenApiKeyIsNotFound() {
            when(ctx.getInternalAttribute(ATTR_INTERNAL_SECURITY_TOKEN))
                .thenReturn(SecurityToken.builder().tokenType(SecurityToken.TokenType.MD5_API_KEY.name()).tokenValue(API_KEY_MD5).build());
            mockApiKeyService(null);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.authenticate(ctx).test();

            obs.assertError(throwable -> throwable.getMessage().equals("API_KEY_INVALID"));

            verify(ctx, never()).setAttribute(any(), any());
        }

        @Test
        void authenticate_shouldNotCompleteWhenApiKeyIsNotValid() {
            when(ctx.getInternalAttribute(ATTR_INTERNAL_SECURITY_TOKEN))
                .thenReturn(SecurityToken.builder().tokenType(SecurityToken.TokenType.MD5_API_KEY.name()).tokenValue(API_KEY_MD5).build());
            final ApiKey apiKey = buildApiKey();
            apiKey.setExpireAt(new Date(System.currentTimeMillis() - 3600000));
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.authenticate(ctx).test();

            obs.assertError(throwable -> throwable.getMessage().equals("API_KEY_INVALID"));

            verify(ctx).setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
            verify(ctx).setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
            verify(ctx).setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
            verify(ctx).setAttribute(ATTR_API_KEY, apiKey.getKey());
        }

        @Test
        void authenticate_shouldNotCompleteWhenApiKeyIsRevoked() {
            when(ctx.getInternalAttribute(ATTR_INTERNAL_SECURITY_TOKEN))
                .thenReturn(SecurityToken.builder().tokenType(SecurityToken.TokenType.MD5_API_KEY.name()).tokenValue(API_KEY_MD5).build());
            final ApiKey apiKey = buildApiKey();
            apiKey.setRevoked(true);
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.authenticate(ctx).test();

            obs.assertError(throwable -> throwable.getMessage().equals("API_KEY_INVALID"));

            verify(ctx).setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
            verify(ctx).setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
            verify(ctx).setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
            verify(ctx).setAttribute(ATTR_API_KEY, apiKey.getKey());
        }

        @Test
        void authenticate_shouldNotCompleteWhenApiKeyIsValidButPasswordDoesNotCorrespond_withPlain() {
            PlainAuthenticateCallback plainAuthenticateCallback = new PlainAuthenticateCallback("UNKNOWN_API_KEY".toCharArray());

            when(ctx.callbacks()).thenReturn(new Callback[] { plainAuthenticateCallback });
            when(ctx.getInternalAttribute(ATTR_INTERNAL_SECURITY_TOKEN))
                .thenReturn(SecurityToken.builder().tokenType(SecurityToken.TokenType.MD5_API_KEY.name()).tokenValue(API_KEY_MD5).build());
            final ApiKey apiKey = buildApiKey();
            mockApiKeyService(apiKey);

            final ApiKeyPolicy cut = new ApiKeyPolicy(configuration);
            final TestObserver<Void> obs = cut.authenticate(ctx).test();

            obs.assertError(throwable -> throwable.getMessage().equals("API_KEY_INVALID"));

            verify(ctx).setAttribute(ContextAttributes.ATTR_APPLICATION, apiKey.getApplication());
            verify(ctx).setAttribute(ContextAttributes.ATTR_SUBSCRIPTION_ID, apiKey.getSubscription());
            verify(ctx).setAttribute(ContextAttributes.ATTR_PLAN, apiKey.getPlan());
            verify(ctx).setAttribute(ATTR_API_KEY, apiKey.getKey());
        }

        private void mockApiKeyService(ApiKey apiKey) {
            when(ctx.getComponent(ApiKeyService.class)).thenReturn(apiKeyService);
            when(ctx.getAttribute(ATTR_API)).thenReturn(API_ID);
            when(apiKeyService.getByApiAndMd5Key(API_ID, API_KEY_MD5)).thenReturn(Optional.ofNullable(apiKey));
        }
    }

    private ApiKey buildApiKey() {
        return buildApiKey(API_KEY);
    }

    private ApiKey buildApiKey(String key) {
        final ApiKey apiKey = new ApiKey();
        apiKey.setRevoked(false);
        apiKey.setExpireAt(EXPIRE_AT);
        apiKey.setPlan(PLAN_ID);
        apiKey.setApplication(APPLICATION_ID);
        apiKey.setSubscription(SUBSCRIPTION_ID);
        apiKey.setKey(key);
        return apiKey;
    }
}
