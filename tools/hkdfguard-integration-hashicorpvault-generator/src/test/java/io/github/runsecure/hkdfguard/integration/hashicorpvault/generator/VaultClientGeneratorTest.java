package io.github.runsecure.hkdfguard.integration.hashicorpvault.generator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class VaultClientGeneratorTest {
    private static final String P = "io/github/runsecure/hkdfguard/integration/hashicorpvault/";

    // --- The library's own generated code -------------------------------------------------------

    @Test
    void theGeneratedCode_IsWhatTheSpecGenerates() throws IOException {
        var library = library();
        var expected = VaultClientGenerator.generate(Files.readString(library.resolve("openapi.json")),
                Files.readString(library.resolve("generator.json")));

        var generated = library.resolve("src/generated/java");
        var onDisk = new TreeMap<String, String>();
        try (var walk = Files.walk(generated)) {
            for (var file : walk.filter(p -> p.toString().endsWith(".java")).toList())
                onDisk.put(generated.relativize(file).toString().replace('\\', '/'), Files.readString(file).replace("\r\n", "\n"));
        }

        assertEquals(expected.keySet(), onDisk.keySet(), "src/generated/java isn't what openapi.json generates: regenerate it.");
        for (var file : expected.entrySet())
            assertEquals(file.getValue(), onDisk.get(file.getKey()), file.getKey() + " differs from what openapi.json generates: regenerate it.");
    }

    @Test
    void theGeneratedApi_IsTheSubsetGeneratorJsonNames() throws IOException {
        var library = library();
        var files = VaultClientGenerator.generate(Files.readString(library.resolve("openapi.json")),
                Files.readString(library.resolve("generator.json")));

        var apis = new TreeMap<String, TreeSet<String>>();
        var method = Pattern.compile("public CompletableFuture<.*> (\\w+)Async\\(.*VaultRequestOptions options\\)");
        for (var file : files.entrySet()) {
            if (!file.getKey().endsWith("Api.java"))
                continue;
            var names = new TreeSet<String>();
            var matcher = method.matcher(file.getValue());
            while (matcher.find())
                names.add(Character.toUpperCase(matcher.group(1).charAt(0)) + matcher.group(1).substring(1));
            apis.put(file.getKey().substring(P.length()), names);
        }

        assertEquals(List.of("AuthApi.java", "SecretsApi.java", "SystemApi.java"), List.copyOf(apis.keySet()));
        assertTrue(apis.get("AuthApi.java").contains("AppRoleLogin"));
        assertTrue(apis.get("AuthApi.java").contains("TokenRenewSelf"));
        assertFalse(apis.get("AuthApi.java").contains("AppRoleWriteRole"));
        assertFalse(apis.get("AuthApi.java").contains("TokenWriteRole"));
        assertTrue(apis.get("SecretsApi.java").stream().allMatch(m -> m.matches("^(KvV1|KvV2|Cubbyhole|Transit).*")));
        assertEquals(List.of("LeaderStatus", "MountsListSecretsEngines", "ReadHealthStatus", "ReadWrappingProperties", "Rewrap", "SealStatus",
                "Unwrap", "Wrap"), List.copyOf(apis.get("SystemApi.java")));
        assertEquals(35, apis.get("AuthApi.java").size());
        assertEquals(60, apis.get("SecretsApi.java").size());
    }

    // --- What the generator produces ------------------------------------------------------------

    @Test
    void theGenerator_LeavesOutDuplicatesAndEnterpriseStubs_AndTheirSchemas() {
        var files = VaultClientGenerator.generate(spec("""
                "/a/{a_mount_path}/item/{name}": {
                  "parameters": [
                    {"name": "name", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The item's <name>."},
                    {"name": "a_mount_path", "in": "path", "required": true, "schema": {"type": "string", "default": "a"}}
                  ],
                  "x-vault-sudo": true,
                  "get": {"operationId": "a-read", "tags": ["secrets"], "summary": "Reads & returns.",
                          "parameters": [{"name": "list", "in": "query", "required": true, "schema": {"type": "string", "enum": ["true"]}},
                                         {"name": "version", "in": "query", "schema": {"type": "integer"}},
                                         {"name": "options", "in": "query", "schema": {"type": "boolean", "default": false}},
                                         {"name": "class", "in": "query", "schema": {"type": "integer", "format": "int64"}}],
                          "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AReadResponse"}}}}}},
                  "post": {"operationId": "a-write", "tags": ["secrets"], "deprecated": true,
                           "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A_writeRequest"}}}},
                           "responses": {"204": {"description": "No Content"}}},
                  "delete": {"operationId": "a-delete2", "tags": ["secrets"], "responses": {"204": {"description": "No Content"}}}
                },
                "/sys/stub": {"get": {"operationId": "enterprise-stub-read", "tags": ["system"], "responses": {}}},
                "/sys/thing": {"post": {"operationId": "thing", "tags": ["custom"], "x-vault-unauthenticated": true, "description": "Does a thing.",
                               "requestBody": {"content": {"application/json": {"schema": {"type": "object", "additionalProperties": true}}}},
                               "responses": {"200": {"description": "OK"}}}}
                """, """
                "AReadResponse": {"type": "object", "properties": {
                  "a_read_response": {"type": "string"},
                  "ttl": {"type": "string", "format": "duration", "default": "1h", "enum": ["1h", "2h"]},
                  "when": {"type": "string", "format": "date-time"},
                  "count": {"type": "integer", "format": "int64"}, "rate": {"type": "number"}, "ok": {"type": "boolean"},
                  "list": {"type": "array"}, "ints": {"type": "array", "items": {"type": "integer"}},
                  "map": {"type": "object"}, "typed_map": {"type": "object", "additionalProperties": {"type": "string"}},
                  "any": {}, "old": {"type": "string", "deprecated": true}, "Ok": {"type": "boolean"},
                  "class": {"type": "string"}, "default": {"type": "string"}, "default_value": {"type": "string"}}},
                "A_writeRequest": {"type": "object", "required": ["name"], "properties": {
                  "name": {"type": "string"}, "map": {"type": "object"}, "list": {"type": "array"}, "any": {},
                  "ref": {"$ref": "#/components/schemas/AReadResponse"},
                  "refs": {"type": "array", "items": {"$ref": "#/components/schemas/AReadResponse"}},
                  "nested": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}}}},
                "ADelete2Response": {"type": "object"},
                "EnterpriseStubReadResponse": {"type": "object"},
                "Unused": {"type": "object", "description": "Not used."},
                "UnusedRequest": {"type": "object"}
                """), null);

        assertEquals(List.of(P + "CustomApi.java", P + "SecretsApi.java", P + "VaultApis.java", P + "schema/AReadResponse.java",
                P + "schema/AWriteRequest.java", P + "schema/Unused.java", P + "schema/UnusedRequest.java"), List.copyOf(files.keySet()));

        var secrets = files.get(P + "SecretsApi.java");
        assertContains("public CompletableFuture<VaultResponse<AReadResponse>> aReadAsync(String name, int version, boolean optionsParameter, "
                + "long classValue, VaultRequestOptions options)", secrets);
        assertContains("public CompletableFuture<VaultResponse<AReadResponse>> aReadAsync(String name, int version, boolean optionsParameter, "
                + "long classValue) {\n        return aReadAsync(name, version, optionsParameter, classValue, null);", secrets);
        assertContains("var requestPath = \"/v1/a/\" + VaultClient.escapePathSegment(VaultClient.mountPathOr(options, \"a\")) + \"/item/\" "
                + "+ VaultClient.escapePathSegment(name);", secrets);
        assertContains("query.add(Map.entry(\"list\", \"true\"));", secrets);
        assertContains("query.add(Map.entry(\"options\", VaultClient.formatQueryValue(optionsParameter)));", secrets);
        assertContains("return client.sendAsync(\"GET\", requestPath, null, query, options, AReadResponse::fromJson);", secrets);
        assertContains("     * Reads &amp; returns.\n", secrets);
        assertContains("@param name The item's &lt;name&gt;.", secrets);
        assertContains("@param optionsParameter The options query parameter. Vault's default: false.", secrets);
        assertContains("Needs a token with sudo capability.", secrets);
        assertContains("{@code GET /v1/a/{a_mount_path}/item/{name}} with {@code list=true}.", secrets);
        assertContains("Its {@code mountPath} is where the secrets engine is mounted, \"a\" by default.", secrets);
        assertContains("@deprecated Deprecated by Vault.\n     */\n    @Deprecated\n    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> "
                + "aWriteAsync(String name, AWriteRequest request, VaultRequestOptions options)", secrets);
        assertContains("@Deprecated\n    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> aWriteAsync(String name, AWriteRequest request) {", secrets);
        assertContains("Objects.requireNonNull(request, \"request\");", secrets);
        assertContains("import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.AWriteRequest;", secrets);
        assertContains("/** Vault's secrets engines. Reached through {@link VaultClient#secrets()}. */", secrets);
        assertFalse(secrets.contains("aDelete2"));

        var custom = files.get(P + "CustomApi.java");
        assertContains("thingAsync(Map<String, ?> request, VaultRequestOptions options)", custom);
        assertContains("As {@link #thingAsync(Map, VaultRequestOptions)}, with no options.", custom);
        assertContains("return client.sendAsync(\"POST\", requestPath, request, query, options, JsonValue::readJsonMap);", custom);
        assertContains("     * Does a thing.\n", custom);
        assertContains("Needs no token.", custom);
        assertContains("Vault's \"custom\" endpoints.", custom);
        assertContains("default CustomApi custom() {\n        return new CustomApi((VaultClient) this);", files.get(P + "VaultApis.java"));
        assertContains("public sealed interface VaultApis permits VaultClient {", files.get(P + "VaultApis.java"));

        var response = files.get(P + "schema/AReadResponse.java");
        assertContains("public String getAReadResponseValue()", response);
        assertContains("A duration: seconds, or a Go duration such as \"24h\". One of: \"1h\", \"2h\". Vault's default: \"1h\".", response);
        assertContains("public OffsetDateTime getWhen()", response);
        assertContains("public Long getCount()", response);
        assertContains("public Double getRate()", response);
        assertContains("public List<JsonValue> getList()", response);
        assertContains("public List<Integer> getInts()", response);
        assertContains("public Map<String, JsonValue> getMap()", response);
        assertContains("public Map<String, String> getTypedMap()", response);
        assertContains("public JsonValue getAny()", response);
        assertContains("@Deprecated\n    public String getOld()", response);
        assertContains("public Boolean getOk2()", response);
        assertContains("public String getClassValue()", response);
        assertContains("private String defaultValue;", response);
        assertContains("private String defaultValue2;", response);
        assertContains("public AReadResponse setAReadResponseValue(String value) {", response);
        assertContains("model.when = json.member(\"when\").readDateTime();", response);
        assertContains("model.list = json.member(\"list\").readList(JsonValue::readJson);", response);
        assertContains("model.typedMap = json.member(\"typed_map\").readMap(JsonValue::readString);", response);
        assertContains("model.map = json.member(\"map\").readJsonMap();", response);
        assertContains("model.any = json.member(\"any\").readJson();", response);
        assertContains("if (this.ok2 != null)\n            writer.name(\"Ok\").value(this.ok2);", response);
        assertContains("/** The data {@link io.github.runsecure.hkdfguard.integration.hashicorpvault.SecretsApi#aReadAsync} returns. */", response);

        var request = files.get(P + "schema/AWriteRequest.java");
        assertContains("public final class AWriteRequest implements VaultModel {", request);
        assertContains("if (this.name == null)\n            throw new IllegalStateException(\"AWriteRequest's name is required.\");", request);
        assertContains("public Map<String, Object> getMap()", request);
        assertContains("public List<Object> getList()", request);
        assertContains("public Object getAny()", request);
        assertContains("public AReadResponse getRef()", request);
        assertContains("model.map = json.member(\"map\").readMap(JsonValue::readObject);", request);
        assertContains("model.ref = json.member(\"ref\").readModel(AReadResponse::fromJson);", request);
        assertContains("model.refs = json.member(\"refs\").readList(v0 -> v0.readModel(AReadResponse::fromJson));", request);
        assertContains("model.nested = json.member(\"nested\").readList(v0 -> v0.readList(JsonValue::readString));", request);
        assertContains("/** The request body of {@link io.github.runsecure.hkdfguard.integration.hashicorpvault.SecretsApi#aWriteAsync}. */", request);

        assertContains("/** Not used. */", files.get(P + "schema/Unused.java"));
        assertContains("/** The UnusedRequest schema. */", files.get(P + "schema/UnusedRequest.java"));
        assertTrue(files.values().stream().allMatch(f -> f.indexOf('\r') < 0));
        assertTrue(files.values().stream().allMatch(f -> f.startsWith("// Generated by hkdfguard-integration-hashicorpvault-generator from "
                + "openapi.json (HashiCorp Vault API 9.9.9).\n")));
    }

    @Test
    void prose_CantBreakOutOfItsJavadoc() {
        var files = VaultClientGenerator.generate(spec("""
                "/x": {"get": {"operationId": "x", "tags": ["system"], "summary": "Ends */ here, @see \\\\u0041 {@code x}.", "responses": {}}}
                """, ""), null);

        assertContains("Ends *&#47; here, &#64;see &#92;u0041 {&#64;code x}.", files.get(P + "SystemApi.java"));
    }

    static List<Object[]> refusals() {
        return List.of(
                new Object[] {"{\"/x\": {\"get\": {\"tags\": [\"system\"], \"responses\": {}}}}", "{}", "no operationId"},
                new Object[] {"{\"/x\": {\"get\": {\"operationId\": \"x\", \"responses\": {}}}}", "{}", "has 0 tags"},
                new Object[] {"{\"/x\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"a\", \"b\"], \"responses\": {}}}}", "{}", "has 2 tags"},
                new Object[] {"{\"/x\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"parameters\": [{\"name\": \"h\", \"in\": \"header\", "
                        + "\"schema\": {\"type\": \"string\"}}], \"responses\": {}}}}", "{}", "header parameter"},
                new Object[] {"{\"/x\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"parameters\": [{\"name\": \"q\", \"in\": \"query\", "
                        + "\"schema\": {\"type\": \"array\"}}], \"responses\": {}}}}", "{}", "only string, integer and boolean"},
                new Object[] {"{\"/x\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"parameters\": [{\"name\": \"q\", \"in\": \"query\"}], "
                        + "\"responses\": {}}}}", "{}", "is a typeless"},
                new Object[] {"{\"/x/{y}\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"responses\": {}}}}", "{}",
                        "placeholder {y} with no parameter"},
                new Object[] {"{\"/x/{q}\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"parameters\": [{\"name\": \"q\", \"in\": \"query\", "
                        + "\"schema\": {\"type\": \"string\"}}], \"responses\": {}}}}", "{}", "placeholder {q} with no parameter"},
                new Object[] {"{\"/{m_mount_path}\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"secrets\"], \"parameters\": [{\"name\": \"m_mount_path\", "
                        + "\"in\": \"path\", \"schema\": {\"type\": \"string\"}}], \"responses\": {}}}}", "{}", "has no default"},
                new Object[] {"{\"/x\": {\"post\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"requestBody\": {\"content\": {\"text/plain\": "
                        + "{\"schema\": {\"type\": \"string\"}}}}, \"responses\": {}}}}", "{}", "isn't only application/json"},
                new Object[] {"{\"/x\": {\"post\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"requestBody\": {\"content\": {\"application/json\": "
                        + "{\"schema\": {\"type\": \"string\"}}}}, \"responses\": {}}}}", "{}", "neither a $ref nor a free-form object"},
                new Object[] {"{\"/x\": {\"post\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"requestBody\": {\"content\": {\"application/json\": "
                        + "{\"schema\": {\"$ref\": \"#/definitions/X\"}}}}, \"responses\": {}}}}", "{}", "Unsupported $ref"},
                new Object[] {"{\"/x\": {\"post\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"requestBody\": {\"content\": {\"application/json\": "
                        + "{\"schema\": {\"$ref\": \"#/components/schemas/Missing\"}}}}, \"responses\": {}}}}", "{}", "missing or excluded"},
                new Object[] {"{}", "{\"S\": {\"type\": \"string\"}}", "isn't an object"},
                new Object[] {"{}", "{\"S\": {\"type\": \"object\", \"properties\": {\"p\": {\"type\": \"object\", \"properties\": {}}}}}",
                        "properties of its own"},
                new Object[] {"{}", "{\"S\": {\"type\": \"object\", \"properties\": {\"p\": {\"type\": \"tuple\"}}}}", "type 'tuple'"},
                new Object[] {"{}", "{\"A_b\": {\"type\": \"object\"}, \"AB\": {\"type\": \"object\"}}", "would all be named AB"});
    }

    @ParameterizedTest
    @MethodSource("refusals")
    void theGenerator_RefusesWhatItDoesntHandle(String paths, String schemas, String message) {
        var e = assertThrows(IllegalArgumentException.class, () -> VaultClientGenerator.generate(
                spec(paths.substring(1, paths.length() - 1), schemas.substring(1, schemas.length() - 1)), null));

        assertContains(message, e.getMessage());
    }

    @Test
    void theGenerator_LetsAnOperationOverrideAPathParameter_AndTypesItsFirst2xxResponse() {
        var files = VaultClientGenerator.generate("""
                {"openapi": "3.0.2", "info": {"title": "test", "version": null},
                 "paths": {
                   "/x/{name}": {
                     "x-vault-unauthenticated": true,
                     "parameters": [{"name": "name", "in": "path", "description": "Shared.", "schema": {"type": "string"}}],
                     "get": {"operationId": "x-read", "tags": ["system"],
                             "parameters": [{"name": "name", "in": "path", "description": "Overridden.", "schema": {"type": "string"}}],
                             "responses": {"400": {"description": "Bad"},
                                           "200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/XResponse"}}}}}},
                     "delete": {"operationId": "x-delete", "tags": ["system"], "x-vault-sudo": true}
                   }},
                 "components": {"schemas": {"XResponse": {"type": "object"}}}}
                """, null);

        var api = files.get(P + "SystemApi.java");
        assertContains("HashiCorp Vault API ).", api);
        assertContains("@param name Overridden.", api);
        // The read takes its own; only the delete, which doesn't override it, takes the path's (in both overloads).
        assertEquals(2, api.split("@param name Shared\\.", -1).length - 1);
        assertContains("CompletableFuture<VaultResponse<XResponse>> xReadAsync(String name, VaultRequestOptions options)", api);
        assertContains("CompletableFuture<VaultResponse<Map<String, JsonValue>>> xDeleteAsync(String name, VaultRequestOptions options)", api);
        assertEquals(2, api.split("Needs no token\\.", -1).length - 1);
        assertEquals(1, api.split("Needs a token with sudo capability\\.", -1).length - 1);
    }

    private static final String NARROWING_PATHS = """
            "/a": {
              "get": {"operationId": "a-read", "tags": ["secrets"],
                      "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AReadResponse"}}}}}},
              "post": {"operationId": "a-write", "tags": ["secrets"],
                       "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/AWriteRequest"}}}},
                       "responses": {"204": {"description": "No Content"}}}
            },
            "/b": {"get": {"operationId": "b-read", "tags": ["identity"],
                           "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BReadResponse"}}}}}}}
            """;

    private static final String NARROWING_SCHEMAS = """
            "AReadResponse": {"type": "object", "properties": {"item": {"$ref": "#/components/schemas/Item"},
                                                                "items": {"type": "array", "items": {"$ref": "#/components/schemas/Other"}}}},
            "Item": {"type": "object", "properties": {"inner": {"$ref": "#/components/schemas/Inner"}}},
            "Inner": {"type": "object", "properties": {"back": {"$ref": "#/components/schemas/Item"}}},
            "Other": {"type": "object"},
            "AWriteRequest": {"type": "object"},
            "BReadResponse": {"type": "object"},
            "Unused": {"type": "object"}
            """;

    @Test
    void anIncludeList_KeepsOnlyItsOperations_TheSchemasTheyUse_AndTheirClasses() {
        var files = VaultClientGenerator.generate(spec(NARROWING_PATHS, NARROWING_SCHEMAS), "{\"description\": \"test\", \"include\": [\"^ARead$\"]}");

        assertEquals(List.of(P + "SecretsApi.java", P + "VaultApis.java", P + "schema/AReadResponse.java", P + "schema/Inner.java",
                P + "schema/Item.java", P + "schema/Other.java"), List.copyOf(files.keySet()));
        assertContains("aReadAsync", files.get(P + "SecretsApi.java"));
        assertFalse(files.get(P + "SecretsApi.java").contains("aWriteAsync"));
        assertFalse(files.get(P + "VaultApis.java").contains("Identity"));
    }

    @Test
    void withoutSettings_OrAnIncludeList_EverythingIsGenerated() {
        var all = VaultClientGenerator.generate(spec(NARROWING_PATHS, NARROWING_SCHEMAS), null);

        assertEquals(all.keySet(), VaultClientGenerator.generate(spec(NARROWING_PATHS, NARROWING_SCHEMAS), "{\"description\": \"nothing narrowed\"}").keySet());
        assertTrue(all.containsKey(P + "schema/Unused.java"));
        assertTrue(all.containsKey(P + "IdentityApi.java"));
        // Tags in vault-client-go's order.
        var apis = all.get(P + "VaultApis.java");
        assertTrue(apis.indexOf("IdentityApi identity()") < apis.indexOf("SecretsApi secrets()"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "{\"include\": [\"^ARead$\", \"^Missing$\"]}|'^Missing$' matches no operation",
            "{\"include\": []}|non-empty array",
            "{\"include\": \"^ARead$\"}|non-empty array",
            "{\"include\": [1]}|non-empty array",
            "{\"include\": [\"(\"]}|isn't a regular expression",
            "{\"exclude\": [\"x\"]}|Unknown generator setting 'exclude'",
            "[\"^ARead$\"]|must be a JSON object",
            "not json|aren't JSON",
    })
    void badSettings_AreRefused(String settings, String message) {
        var e = assertThrows(IllegalArgumentException.class, () -> VaultClientGenerator.generate(spec(NARROWING_PATHS, NARROWING_SCHEMAS), settings));

        assertContains(message, e.getMessage());
    }

    @Test
    void anIncludedOperationsMissingSchema_IsRefused() {
        var e = assertThrows(IllegalArgumentException.class, () -> VaultClientGenerator.generate(
                spec(NARROWING_PATHS, NARROWING_SCHEMAS.replace(
                        "\"Inner\": {\"type\": \"object\", \"properties\": {\"back\": {\"$ref\": \"#/components/schemas/Item\"}}},", "")),
                "{\"include\": [\"^ARead$\"]}"));

        assertContains("Schema Inner is referred to but missing", e.getMessage());
    }

    // --- Naming ---------------------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({"kv-v2-read, KvV2Read", "hcp_link_resource_ID, HcpLinkResourceID", "2fa, _2fa", "--, Value"})
    void pascal_NamesAsOpenApiGeneratorDoes(String name, String expected) {
        assertEquals(expected, Java.pascal(name));
    }

    @ParameterizedTest
    @CsvSource({"role_name, roleName", "class, classValue", "default, defaultValue", "2fa, _2fa"})
    void camel_EscapesKeywords(String name, String expected) {
        assertEquals(expected, Java.camel(name));
    }

    @Test
    void literal_EscapesWhatAJavaStringCantHoldAsItIs() {
        assertEquals("\"a\\\\b\\\"c\\n\\r\\t\\u0001\"", Java.literal("a\\b\"c\n\r\t\u0001"));
    }

    @Test
    void json_ReadsWhatTheSpecHolds_AndWritesItBack() {
        var value = Json.parse(" {\"a\": [1, -2.5e3, true, false, null], \"b\": \"\\u00e9\\n\\\"\", \"c\": {}} ");

        assertEquals("{\"a\":[1,-2.5e3,true,false,null],\"b\":\"\u00e9\\n\\\"\",\"c\":{}}", Json.write(value));
        assertEquals(List.of("a", "b", "c"), List.copyOf(((Map<?, ?>) value).keySet()));
        for (var bad : List.of("", "{", "[1,]", "{\"a\" 1}", "\"\\x\"", "1 2", "tru", "-"))
            assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
    }

    // --- The command ----------------------------------------------------------------------------

    @Test
    void theGeneratorCommand_TakesSettings_GivenOrBesideTheSpec(@TempDir Path directory) throws IOException {
        var spec = directory.resolve("spec.json");
        var given = directory.resolve("narrow.json");
        Files.writeString(spec, spec(NARROWING_PATHS, NARROWING_SCHEMAS));
        Files.writeString(given, "{\"include\": [\"^BRead$\"]}");
        Files.writeString(directory.resolve(GeneratorCommand.SETTINGS_FILE_NAME), "{\"include\": [\"^ARead$\"]}");

        var beside = run(directory, "--spec", spec.toString(), "--output", directory.resolve("beside").toString());
        var givenRun = run(directory, "--spec", spec.toString(), "--settings", given.toString(), "--output", directory.resolve("given").toString());

        assertContains("with " + directory.resolve(GeneratorCommand.SETTINGS_FILE_NAME).toAbsolutePath().normalize(), beside.message());
        assertTrue(Files.exists(directory.resolve("beside").resolve(P + "SecretsApi.java")));
        assertContains("with " + given.toAbsolutePath().normalize(), givenRun.message());
        assertTrue(Files.exists(directory.resolve("given").resolve(P + "IdentityApi.java")));
        assertFalse(Files.exists(directory.resolve("given").resolve(P + "SecretsApi.java")));
    }

    @Test
    void theGeneratorCommand_WritesOnlyChangedFiles_AndDeletesStaleOnes(@TempDir Path directory) throws IOException {
        var spec = directory.resolve("spec.json").toAbsolutePath().normalize();
        var output = directory.resolve("out").toAbsolutePath().normalize();
        Files.writeString(spec, spec("\"/sys/x\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"responses\": {}}}", ""));
        Files.createDirectories(output.resolve(P + "schema"));
        Files.writeString(output.resolve(P + "schema/Stale.java"), "stale");
        Files.writeString(output.resolve("keep.txt"), "not generated");

        assertEquals(new Result(0, "2 files from " + spec + ": 2 written, 0 unchanged, 1 stale deleted, in " + output + "."),
                run(directory, "--spec", spec.toString(), "--output", output.toString()));
        var written = Files.getLastModifiedTime(output.resolve(P + "SystemApi.java"));
        assertEquals(new Result(0, "2 files from " + spec + ": 0 written, 2 unchanged, 0 stale deleted, in " + output + "."),
                run(directory, "--spec", spec.toString(), "--output", output.toString()));
        assertEquals(written, Files.getLastModifiedTime(output.resolve(P + "SystemApi.java")));
        assertFalse(Files.exists(output.resolve(P + "schema/Stale.java")));
        assertTrue(Files.exists(output.resolve("keep.txt")));
    }

    @Test
    void theGeneratorCommand_DefaultsToTheLibrarysSpec_FoundFromTheRepositoryRoot(@TempDir Path directory) {
        var library = library().toAbsolutePath().normalize();

        var result = run(library.resolve("src/generated/java"), "--output", directory.toString());

        assertEquals(0, result.code());
        assertContains(library.resolve("openapi.json").toString(), result.message());
        assertTrue(Files.exists(directory.resolve(P + "schema/KvV2ReadResponse.java")));
    }

    @Test
    void theGeneratorCommand_DefaultsTheOutput_UnderTheRepositoryRoot(@TempDir Path directory) throws IOException {
        // A stand-in repository, so nothing under the real one is written.
        Files.writeString(directory.resolve("pom.xml"), "<project><artifactId>hkdfguard-parent</artifactId></project>");
        var spec = directory.resolve("spec.json");
        Files.writeString(spec, spec("\"/sys/x\": {\"get\": {\"operationId\": \"x\", \"tags\": [\"system\"], \"responses\": {}}}", ""));

        assertEquals(0, run(directory.resolve("."), "--spec", spec.toString()).code());
        assertTrue(Files.exists(directory.resolve(GeneratorCommand.LIBRARY).resolve("src/generated/java").resolve(P + "SystemApi.java")));
    }

    @ParameterizedTest
    @CsvSource(nullValues = "null", value = {"--bogus", "--spec", "null"})
    void theGeneratorCommand_RefusesBadArguments_OrNoRepository(String argument, @TempDir Path directory) {
        var result = run(directory, argument == null ? new String[0] : new String[] {argument});

        assertEquals(2, result.code());
        assertContains(argument == null ? "repository root" : "Usage", result.message());
    }

    private record Result(int code, String message) {
    }

    private static Result run(Path currentDirectory, String... args) {
        var buffer = new ByteArrayOutputStream();
        try (var output = new PrintStream(buffer, true, StandardCharsets.UTF_8)) {
            var code = GeneratorCommand.run(List.of(args), currentDirectory, output, output);
            return new Result(code, buffer.toString(StandardCharsets.UTF_8).trim());
        }
    }

    private static String spec(String paths, String schemas) {
        return "{\"openapi\": \"3.0.2\", \"info\": {\"title\": \"test\", \"version\": \"9.9.9\"}, \"paths\": {" + paths
                + "}, \"components\": {\"schemas\": {" + schemas + "}}}";
    }

    private static Path library() {
        var directory = System.getProperty("hkdfguard.integration.dir");
        return directory != null ? Path.of(directory) : Path.of("../../" + GeneratorCommand.LIBRARY);
    }

    private static void assertContains(String expected, String actual) {
        assertTrue(actual.contains(expected), () -> "Expected to find:\n" + expected + "\nin:\n" + actual);
    }
}
