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

import static io.gravitee.policy.apikey.ApiKeyPolicy.*;

import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.api.PolicyContext;
import io.gravitee.policy.api.PolicyContextProvider;
import io.gravitee.policy.api.PolicyContextProviderAware;
import org.springframework.core.env.Environment;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ApiKeyPolicyInitializer implements PolicyContext, PolicyContextProviderAware {

    private Configuration configuration;

    @Override
    public void onActivation() throws Exception {
        if (API_KEY_HEADER == null || API_KEY_QUERY_PARAMETER == null) {
            if (configuration == null) {
                API_KEY_HEADER = DEFAULT_API_KEY_HEADER_PARAMETER;
                API_KEY_QUERY_PARAMETER = DEFAULT_API_KEY_QUERY_PARAMETER;
            } else {
                API_KEY_HEADER = configuration.getProperty(API_KEY_HEADER_PROPERTY, DEFAULT_API_KEY_HEADER_PARAMETER);
                API_KEY_QUERY_PARAMETER = configuration.getProperty(API_KEY_QUERY_PARAMETER_PROPERTY, DEFAULT_API_KEY_QUERY_PARAMETER);
            }
        }
    }

    @Override
    public void onDeactivation() throws Exception {
        // Nothing to do.
    }

    @Override
    public void setPolicyContextProvider(PolicyContextProvider policyContextProvider) {
        // FIXME: get node Configuration
        this.configuration = policyContextProvider.getComponent(Configuration.class);
    }
}
