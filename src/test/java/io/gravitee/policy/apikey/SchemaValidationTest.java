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

import static org.assertj.core.api.Assertions.*;

import io.gravitee.json.validation.InvalidJsonException;
import io.gravitee.json.validation.JsonSchemaValidator;
import io.gravitee.json.validation.JsonSchemaValidatorImpl;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.json.JSONException;
import org.junit.jupiter.api.*;
import org.skyscreamer.jsonassert.JSONAssert;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class SchemaValidationTest {

    static String configurationSchema;

    JsonSchemaValidator validator = new JsonSchemaValidatorImpl();

    @BeforeAll
    static void beforeAll() throws IOException {
        configurationSchema = Files.readString(Path.of("src/main/resources/schemas/schema-form.json"));
    }

    @Nested
    class Configuration {

        @Test
        void should_validate_valid_configuration() throws JSONException {
            String json = """
                 {
                  "propagateApiKey": true,
                  "enableCustomApiKeyHeader": true,
                  "apiKeyHeader": "X-My-Api-Key"
                }
                """;
            String result = validator.validate(configurationSchema, json);
            JSONAssert.assertEquals(
                """
                {
                  "propagateApiKey": true,
                  "enableCustomApiKeyHeader": true,
                  "apiKeyHeader": "X-My-Api-Key"
                }
                """,
                result,
                true
            );
        }

        @Test
        void should_validate_valid_configuration_without_custom_header() throws JSONException {
            String json = """
                 {
                  "propagateApiKey": false,
                  "enableCustomApiKeyHeader": false
                }
                """;
            String result = validator.validate(configurationSchema, json);
            JSONAssert.assertEquals(
                """
                {
                  "propagateApiKey": false,
                  "enableCustomApiKeyHeader": false
                }
                """,
                result,
                true
            );
        }

        @Test
        void should_not_validate_invalid_api_key_header_pattern() {
            String json = """
                 {
                  "propagateApiKey": true,
                  "enableCustomApiKeyHeader": true,
                  "apiKeyHeader": "Invalid Header!"
                }
                """;

            assertThatThrownBy(() -> validator.validate(configurationSchema, json))
                .isInstanceOf(InvalidJsonException.class)
                .hasMessageContaining("#/apiKeyHeader: string [Invalid Header!] does not match pattern");
        }
    }
}
