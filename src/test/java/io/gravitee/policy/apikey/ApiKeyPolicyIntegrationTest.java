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
import io.gravitee.gateway.handlers.api.definition.ApiKey;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.model.Subscription;
import io.reactivex.observers.TestObserver;
import io.vertx.reactivex.core.buffer.Buffer;
import io.vertx.reactivex.ext.web.client.HttpResponse;
import io.vertx.reactivex.ext.web.client.WebClient;
import java.util.Collections;
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
    @DisplayName("Should receive 401 - Unauthorized we calling without an API-Key")
    void shouldGet401IfNoApiKey(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").rxSend().test();

        awaitTerminalEvent(obs);
        obs
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
    @DisplayName("Should access API with API-Key header")
    void shouldAccessApiWithApiKeyHeader(WebClient client) throws TechnicalException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromDb();

        when(getBean(ApiKeyRepository.class).findByKeyAndApi(any(), any())).thenReturn(Optional.of(apiKey));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").putHeader("X-Gravitee-Api-Key", "apiKeyValue").rxSend().test();

        awaitTerminalEvent(obs);
        obs
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
    void shouldAccessApiWithApiKeyQueryParam(WebClient client) throws TechnicalException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromDb();

        when(getBean(ApiKeyRepository.class).findByKeyAndApi(any(), any())).thenReturn(Optional.of(apiKey));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").addQueryParam("api-key", "apiKeyValue").rxSend().test();

        awaitTerminalEvent(obs);
        obs
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
     * Generate the ApiKey object that would be returned by the ApiKeyRepository
     * @return the ApiKey object
     */
    private ApiKey fakeApiKeyFromDb() {
        final io.gravitee.repository.management.model.ApiKey repoApiKey = new io.gravitee.repository.management.model.ApiKey();
        repoApiKey.setApplication("application-id");
        repoApiKey.setSubscription("subscription-id");
        repoApiKey.setPlan("plan-id");
        repoApiKey.setKey("key-id");

        Subscription subscription = new Subscription();
        subscription.setPlan("plan-id");
        subscription.setId("subscription-id");
        subscription.setStatus(Subscription.Status.ACCEPTED);

        return new ApiKey(repoApiKey, subscription);
    }
}
