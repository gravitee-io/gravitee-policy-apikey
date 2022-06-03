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

import static io.gravitee.policy.apikey.ApiKeyPolicy.*;
import static io.gravitee.policy.apikey.ApiKeyPolicy.DEFAULT_API_KEY_QUERY_PARAMETER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.api.PolicyContextProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class ApiKeyPolicyInitializerTest {

    protected static final String MOCK_HEADER = "MockHeader";
    protected static final String MOCK_QUERY_PARAM = "MockQueryParam";

    @Mock
    private Configuration configuration;

    @BeforeEach
    void init() {
        API_KEY_HEADER = null;
        API_KEY_QUERY_PARAMETER = null;
    }

    @Test
    void shouldSetApiKeyHeaderAndQueryParamNamesFromEnvironment() throws Exception {
        final ApiKeyPolicyInitializer initializer = new ApiKeyPolicyInitializer();
        final PolicyContextProvider contextProvider = mock(PolicyContextProvider.class);

        when(contextProvider.getComponent(Configuration.class)).thenReturn(configuration);
        initializer.setPolicyContextProvider(contextProvider);

        when(configuration.getProperty(API_KEY_HEADER_PROPERTY, DEFAULT_API_KEY_HEADER_PARAMETER)).thenReturn(MOCK_HEADER);
        when(configuration.getProperty(API_KEY_QUERY_PARAMETER_PROPERTY, DEFAULT_API_KEY_QUERY_PARAMETER)).thenReturn(MOCK_QUERY_PARAM);
        initializer.onActivation();

        assertEquals(MOCK_HEADER, API_KEY_HEADER);
        assertEquals(MOCK_QUERY_PARAM, API_KEY_QUERY_PARAMETER);
    }

    @Test
    void shouldSetDefaultApiKeyHeaderAndQueryParamNamesWhenNullEnvironment() throws Exception {
        final ApiKeyPolicyInitializer initializer = new ApiKeyPolicyInitializer();
        initializer.onActivation();

        assertEquals(DEFAULT_API_KEY_HEADER_PARAMETER, API_KEY_HEADER);
        assertEquals(DEFAULT_API_KEY_QUERY_PARAMETER, API_KEY_QUERY_PARAMETER);
    }

    @Test
    void shouldNotSetApiKeyHeaderAndQueryParamNamesWhenAlreadySet() throws Exception {
        API_KEY_HEADER = MOCK_HEADER;
        API_KEY_QUERY_PARAMETER = MOCK_QUERY_PARAM;

        final ApiKeyPolicyInitializer initializer = new ApiKeyPolicyInitializer();
        initializer.onActivation();

        assertEquals(MOCK_HEADER, API_KEY_HEADER);
        assertEquals(MOCK_QUERY_PARAM, API_KEY_QUERY_PARAMETER);
    }
}
