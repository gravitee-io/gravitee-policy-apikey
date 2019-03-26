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
package io.gravitee.policy.apikey.configuration;

import java.util.List;
import io.gravitee.policy.api.PolicyConfiguration;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ApiKeyPolicyConfiguration implements PolicyConfiguration {

    private boolean propagateApiKey = false;

    private List<Response> responses;

    public boolean isPropagateApiKey() {
        return propagateApiKey;
    }

    public void setPropagateApiKey(boolean propagateApiKey) {
        this.propagateApiKey = propagateApiKey;
    }

    /**
     * @return the list of configured responses, may be <code>null</code>.
     * @since 1.6.3
     */
    public List<Response> getResponses() {
        return this.responses;
    }

    /**
     * @param responses
     *        the responses to set
     * @since 1.6.3
     */
    public void setResponses(final List<Response> responses) {
        this.responses = responses;
    }
}
