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

/**
 * a type of error to configure a response for.<br/>
 * erzeugt am 06.12.2018
 *
 * @author Oliver Kelling, https://github.com/k-oliver
 * @since 1.6.3
 */
public enum ErrorType {

    /**
     * no API key was send.
     *
     * @since 1.6.3
     */
    MISSING,

    /**
     * API key is wrong, expired or revoked.
     *
     * @since 1.6.3
     */
    WRONG_EXPIRED_REVOKED
}
