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
package io.gravitee.policy.apikey.configuration;

import io.gravitee.common.http.GraviteeHttpHeader;
import io.gravitee.policy.api.PolicyConfiguration;
import java.util.Objects;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ApiKeyPolicyConfiguration implements PolicyConfiguration {

    private boolean propagateApiKey = false;

    @Nullable
    private ApiKeySource source;

    @Nullable
    private String apiKeyHeader;

    /**
     * No longer required since 4.12.x: the custom {@link #apiKeyHeader} is always applied when set.
     * Kept only for backward compatibility with gateways older than 4.12.x. To be removed once those
     * versions are no longer supported.
     */
    @Deprecated
    private boolean enableCustomApiKeyHeader = false;

    public ApiKeySource resolveSource() {
        return Objects.requireNonNullElse(source, ApiKeySource.HEADER);
    }

    /** Header name for HEADER source. Falls back to {@code X-Gravitee-Api-Key} when {@code apiKeyHeader} is blank. */
    public Optional<String> resolveHeaderName() {
        return StringUtils.hasText(apiKeyHeader) ? Optional.of(apiKeyHeader) : Optional.empty();
    }

    /**
     * {@code apiKeyHeader} is intentionally left {@code null} here: a {@code null} plan configuration means
     * "no header explicitly configured on this plan", and must fall through to the gateway-wide
     * {@code policy.api-key.header} setting the same way an explicit empty ({@code {}}) configuration does.
     * Hardcoding {@link GraviteeHttpHeader#X_GRAVITEE_API_KEY} here made {@link #resolveHeaderName()} report a
     * header as "configured" even when none was, which caused the gateway-wide header to be silently ignored
     * for plans with no explicit security configuration (APIM-14651).
     */
    public static final ApiKeyPolicyConfiguration DEFAULT = new ApiKeyPolicyConfiguration(false, ApiKeySource.HEADER, null, false);
}
