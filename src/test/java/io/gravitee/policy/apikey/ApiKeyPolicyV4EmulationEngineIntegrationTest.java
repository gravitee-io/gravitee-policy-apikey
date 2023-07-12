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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.gravitee.gateway.reactive.api.policy.SecurityToken.TokenType.API_KEY;
import static io.vertx.core.http.HttpMethod.GET;
import static java.time.temporal.ChronoUnit.HOURS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.configuration.GatewayConfigurationBuilder;
import io.gravitee.definition.model.Api;
import io.gravitee.definition.model.ExecutionMode;
import io.gravitee.definition.model.Plan;
import io.gravitee.gateway.api.service.ApiKey;
import io.gravitee.gateway.api.service.ApiKeyService;
import io.gravitee.gateway.api.service.Subscription;
import io.gravitee.gateway.api.service.SubscriptionService;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.vertx.core.http.RequestOptions;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.OngoingStubbing;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
@GatewayTest
@DeployApi("/apis/api-key.json")
public class ApiKeyPolicyV4EmulationEngineIntegrationTest extends AbstractPolicyTest<ApiKeyPolicy, ApiKeyPolicyConfiguration> {

    /**
     * Override api plans to have a published API_KEY one.
     * @param api is the api to apply this function code
     */
    @Override
    public void configureApi(Api api) {
        Plan apiKeyPlan = new Plan();
        apiKeyPlan.setId("plan-id");
        apiKeyPlan.setApi(api.getId());
        apiKeyPlan.setSecurity("API_KEY");
        apiKeyPlan.setStatus("PUBLISHED");
        apiKeyPlan.setSecurityDefinition("{\"propagateApiKey\":true}");
        api.setPlans(Collections.singletonList(apiKeyPlan));
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling without an API-Key")
    void shouldGet401IfNoApiKey(HttpClient client) throws InterruptedException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        client
            .rxRequest(GET, "/test")
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with an empty API-Key")
    void shouldGet401IfEmptyApiKey(HttpClient client) throws InterruptedException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        client
            .rxRequest(new RequestOptions().setMethod(GET).setURI("/test").putHeader("X-Gravitee-Api-Key", ""))
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with an API Key, without subscription")
    void shouldGet401IfNoSubscription(HttpClient client) throws InterruptedException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyService.class).getByApiAndKey(any(), any())).thenReturn(Optional.of(apiKey));
        when(getBean(SubscriptionService.class).getByApiAndSecurityToken(any(), any(), any())).thenReturn(Optional.empty());

        client
            .rxRequest(new RequestOptions().setMethod(GET).setURI("/test").putHeader("X-Gravitee-Api-Key", "apiKeyValue"))
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertUnauthorizedResponseBody(body.toString());
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with an API Key, with expired subscription")
    void shouldGet401IfExpiredSubscription(HttpClient client) throws InterruptedException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyService.class).getByApiAndKey(any(), any())).thenReturn(Optional.of(apiKey));
        whenSearchingSubscription(apiKey).thenReturn(Optional.of(fakeSubscriptionFromCache(true)));

        client
            .rxRequest(new RequestOptions().setMethod(GET).setURI("/test").putHeader("X-Gravitee-Api-Key", "apiKeyValue"))
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertUnauthorizedResponseBody(body.toString());
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should access API with API-Key header")
    void shouldAccessApiWithApiKeyHeader(HttpClient client) throws InterruptedException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyService.class).getByApiAndKey(any(), any())).thenReturn(Optional.of(apiKey));
        whenSearchingSubscription(apiKey).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

        client
            .rxRequest(new RequestOptions().setMethod(GET).setURI("/test").putHeader("X-Gravitee-Api-Key", "apiKeyValue"))
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("response from backend");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should access API with API-Key query param")
    void shouldAccessApiWithApiKeyQueryParam(HttpClient client) throws InterruptedException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyService.class).getByApiAndKey(any(), any())).thenReturn(Optional.of(apiKey));
        whenSearchingSubscription(apiKey).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

        client
            .rxRequest(new RequestOptions().setMethod(GET).setURI("/test?api-key=apiKeyValue"))
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("response from backend");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
    }

    /**
     * Generate the ApiKey object that would be returned by the ApiKeyService
     * @return the ApiKey object
     */
    private ApiKey fakeApiKeyFromCache() {
        final ApiKey apiKey = new ApiKey();
        apiKey.setApi("my-api");
        apiKey.setApplication("application-id");
        apiKey.setSubscription("subscription-id");
        apiKey.setPlan("plan-id");
        apiKey.setKey("apiKeyValue");
        return apiKey;
    }

    /**
     * Generate the Subscription object that would be returned by the SubscriptionService
     * @return the Subscription object
     */
    private Subscription fakeSubscriptionFromCache(boolean isExpired) {
        final Subscription subscription = new Subscription();
        subscription.setApplication("application-id");
        subscription.setId("subscription-id");
        subscription.setPlan("plan-id");
        if (isExpired) {
            subscription.setEndingAt(new Date(Instant.now().minus(1, HOURS).toEpochMilli()));
        }
        return subscription;
    }

    protected void assertUnauthorizedResponseBody(String responseBody) {
        assertThat(responseBody).isEqualTo("Unauthorized");
    }

    protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(ApiKey apiKey) {
        return when(
            getBean(SubscriptionService.class)
                .getByApiAndSecurityToken(eq(apiKey.getApi()), securityTokenMatcher(apiKey.getKey()), eq(apiKey.getPlan()))
        );
    }

    private SecurityToken securityTokenMatcher(String apiKeyValue) {
        return argThat(securityToken ->
            securityToken.getTokenType().equals(API_KEY.name()) && securityToken.getTokenValue().equals(apiKeyValue)
        );
    }
}
