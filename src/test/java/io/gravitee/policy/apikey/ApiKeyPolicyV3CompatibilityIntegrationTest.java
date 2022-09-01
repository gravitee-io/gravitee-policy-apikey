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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import io.gravitee.apim.gateway.tests.sdk.configuration.GatewayConfigurationBuilder;
import io.gravitee.definition.model.Api;
import io.gravitee.definition.model.ExecutionMode;
import io.gravitee.gateway.api.service.ApiKey;
import io.gravitee.gateway.api.service.Subscription;
import io.gravitee.gateway.api.service.SubscriptionService;
import java.util.Optional;
import org.junit.jupiter.api.Disabled;
import org.mockito.stubbing.OngoingStubbing;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@Disabled("Temporary disabled to make build pass and waiting for a new version of tests-sdk")
public class ApiKeyPolicyV3CompatibilityIntegrationTest extends ApiKeyPolicyIntegrationTest {

    @Override
    protected void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
        super.configureGateway(gatewayConfigurationBuilder);
        gatewayConfigurationBuilder.set("api.jupiterMode.enabled", "true");
    }

    @Override
    public void configureApi(Api api) {
        super.configureApi(api);
        api.setExecutionMode(ExecutionMode.V3);
    }

    /**
     * This overrides subscription search :
     * - in jupiter its searched with getByApiAndSecurityToken
     * - in V3 its searches with getById
     */
    @Override
    protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(ApiKey apiKey) {
        return when(getBean(SubscriptionService.class).getById(apiKey.getSubscription()));
    }

    /**
     * This overrides 401 response HTTP body content assertion :
     * - in jupiter, it's "unauthorized"
     * - in V3, it contains more information
     */
    @Override
    protected void assertUnauthorizedResponseBody(String responseBody) {
        assertThat(responseBody).isEqualTo("API Key is not valid or is expired / revoked.");
    }
}
