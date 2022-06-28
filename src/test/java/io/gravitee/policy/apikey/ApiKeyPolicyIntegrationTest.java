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
import static java.time.temporal.ChronoUnit.HOURS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.reactivex.observers.TestObserver;
import io.vertx.reactivex.core.buffer.Buffer;
import io.vertx.reactivex.ext.web.client.HttpResponse;
import io.vertx.reactivex.ext.web.client.WebClient;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
@GatewayTest
@DeployApi("/apis/api-key.json")
public class ApiKeyPolicyIntegrationTest extends AbstractPolicyTest<ApiKeyPolicy, ApiKeyPolicyConfiguration> {

    @Override
    protected void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
        super.configureGateway(gatewayConfigurationBuilder);
        gatewayConfigurationBuilder.set("api.jupiterMode.enabled", "true");
        gatewayConfigurationBuilder.set("http.instances", "1");
    }

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
        api.setExecutionMode(ExecutionMode.JUPITER);
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling without an API-Key")
    void shouldGet401IfNoApiKey(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").rxSend().test();

        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.bodyAsString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with an API key, without subscription")
    void shouldGet401IfNoSubscription(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyService.class).getByApiAndKey(any(), any())).thenReturn(Optional.of(apiKey));
        when(getBean(SubscriptionService.class).getById(any())).thenReturn(Optional.empty());

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").putHeader("X-Gravitee-Api-Key", "apiKeyValue").rxSend().test();

        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.bodyAsString()).isEqualTo("API Key is not valid or is expired / revoked.");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with an API key, with expired subscription")
    void shouldGet401IfExpiredSubscription(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyService.class).getByApiAndKey(any(), any())).thenReturn(Optional.of(apiKey));
        when(getBean(SubscriptionService.class).getById(any())).thenReturn(Optional.of(fakeSubscriptionFromCache(true)));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").putHeader("X-Gravitee-Api-Key", "apiKeyValue").rxSend().test();

        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.bodyAsString()).isEqualTo("API Key is not valid or is expired / revoked.");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should access API with API-Key header")
    void shouldAccessApiWithApiKeyHeader(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyService.class).getByApiAndKey(any(), any())).thenReturn(Optional.of(apiKey));
        when(getBean(SubscriptionService.class).getById(apiKey.getSubscription()))
            .thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").putHeader("X-Gravitee-Api-Key", "apiKeyValue").rxSend().test();

        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(response.bodyAsString()).isEqualTo("response from backend");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should access API with API-Key query param")
    void shouldAccessApiWithApiKeyQueryParam(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyService.class).getByApiAndKey(any(), any())).thenReturn(Optional.of(apiKey));
        when(getBean(SubscriptionService.class).getById("subscription-id")).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").addQueryParam("api-key", "apiKeyValue").rxSend().test();

        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(response.bodyAsString()).isEqualTo("response from backend");
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
        apiKey.setApplication("application-id");
        apiKey.setSubscription("subscription-id");
        apiKey.setPlan("plan-id");
        apiKey.setKey("key-id");
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
}
