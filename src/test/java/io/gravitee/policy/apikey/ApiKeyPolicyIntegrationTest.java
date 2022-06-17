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
import io.gravitee.definition.model.Api;
import io.gravitee.definition.model.Plan;
import io.gravitee.gateway.api.cache.ApiKey;
import io.gravitee.gateway.handlers.api.cache.ApiKeyCacheManager;
import io.gravitee.policy.apikey.configuration.ApiKeyPolicyConfiguration;
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
class ApiKeyPolicyIntegrationTest extends AbstractPolicyTest<ApiKeyPolicy, ApiKeyPolicyConfiguration> {

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
    void shouldAccessApiWithApiKeyHeader(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyCacheManager.class).get(any(), any())).thenReturn(Optional.of(apiKey));

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
    void shouldAccessApiWithApiKeyQueryParam(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final ApiKey apiKey = fakeApiKeyFromCache();

        when(getBean(ApiKeyCacheManager.class).get(any(), any())).thenReturn(Optional.of(apiKey));

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
     * Generate the ApiKey object that would be returned by the ApiKeyCacheManager
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
}
