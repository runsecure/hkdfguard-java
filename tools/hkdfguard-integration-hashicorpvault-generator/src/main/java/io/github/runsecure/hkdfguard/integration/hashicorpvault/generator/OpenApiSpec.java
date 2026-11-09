package io.github.runsecure.hkdfguard.integration.hashicorpvault.generator;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * What the generator needs from Vault's OpenAPI document, in document order.
 *
 * @param apiVersion the document's info.version; "" if it has none
 * @param operations every operation, path by path
 * @param schemas    components.schemas, by name
 */
record OpenApiSpec(String apiVersion, List<OpenApiSpec.Operation> operations, Map<String, Object> schemas) {
    private static final List<String> METHODS = List.of("get", "put", "post", "delete", "patch");
    private static final String SCHEMA_PREFIX = "#/components/schemas/";

    /**
     * One endpoint and method.
     *
     * @param method the HTTP method, upper case
     */
    record Operation(String id, String tag, String method, String path, String summary, String description, String pathDescription,
            boolean deprecated, boolean unauthenticated, boolean sudo, List<Parameter> parameters, Object requestSchema,
            Object responseSchema) {
    }

    /**
     * A path or query parameter.
     *
     * @param schema its schema; null if it has none
     */
    record Parameter(String name, String in, String description, Object schema, boolean required) {
        /** Whether this is the path parameter where the auth method or secrets engine is mounted. */
        boolean isMountPath() {
            return in.equals("path") && name.endsWith("_mount_path");
        }
    }

    /**
     * Reads the document root.
     *
     * @throws IllegalArgumentException an operation lacks an id or tag, or uses something the
     *                                  generator doesn't handle
     */
    static OpenApiSpec read(Object root) {
        var version = Json.string(Json.member(root, "info"), "version");
        var operations = new ArrayList<Operation>();
        for (var path : Json.members(Json.member(root, "paths")).entrySet()) {
            var item = path.getValue();
            var shared = parameters(item);
            for (var member : Json.members(item).entrySet()) {
                if (!METHODS.contains(member.getKey()))
                    continue;

                var operation = member.getValue();
                var id = Json.string(operation, "operationId");
                if (id == null)
                    throw new IllegalArgumentException(member.getKey() + " " + path.getKey() + " has no operationId.");
                var tags = Json.member(operation, "tags") instanceof List<?> list ? list : List.of();
                if (tags.size() != 1)
                    throw new IllegalArgumentException("Operation " + id + " has " + tags.size() + " tags; the generator expects exactly one.");

                // Operation parameters first, then the path's that it doesn't override - as openapi-generator orders them.
                var own = parameters(operation);
                var all = new ArrayList<>(own);
                for (var s : shared) {
                    if (own.stream().noneMatch(o -> o.name().equals(s.name()) && o.in().equals(s.in())))
                        all.add(s);
                }

                operations.add(new Operation(id, (String) tags.getFirst(), member.getKey().toUpperCase(Locale.ROOT), path.getKey(),
                        Json.string(operation, "summary"), Json.string(operation, "description"), Json.string(item, "description"),
                        Json.bool(operation, "deprecated"),
                        Json.bool(operation, "x-vault-unauthenticated") || Json.bool(item, "x-vault-unauthenticated"),
                        Json.bool(operation, "x-vault-sudo") || Json.bool(item, "x-vault-sudo"),
                        List.copyOf(all), requestSchema(id, operation), responseSchema(operation)));
            }
        }

        var schemas = Json.members(Json.member(Json.member(root, "components"), "schemas"));
        return new OpenApiSpec(version == null ? "" : version, List.copyOf(operations), schemas);
    }

    /**
     * The schema a $ref names, without its "#/components/schemas/" prefix; null if schema isn't a $ref.
     *
     * @throws IllegalArgumentException the $ref points anywhere else
     */
    static String refName(Object schema) {
        var reference = Json.string(schema, "$ref");
        if (reference == null)
            return null;
        if (!reference.startsWith(SCHEMA_PREFIX))
            throw new IllegalArgumentException("Unsupported $ref '" + reference + "': only " + SCHEMA_PREFIX + "... is handled.");
        return reference.substring(SCHEMA_PREFIX.length());
    }

    private static List<Parameter> parameters(Object element) {
        if (!(Json.member(element, "parameters") instanceof List<?> parameters))
            return List.of();

        var result = new ArrayList<Parameter>();
        for (var p : parameters) {
            result.add(new Parameter(Json.string(p, "name"), Json.string(p, "in"), Json.string(p, "description"),
                    Json.member(p, "schema"), Json.bool(p, "required")));
        }
        return result;
    }

    private static Object requestSchema(String id, Object operation) {
        if (!Json.has(operation, "requestBody"))
            return null;

        var content = Json.members(Json.member(Json.member(operation, "requestBody"), "content"));
        if (!content.containsKey("application/json") || content.size() != 1)
            throw new IllegalArgumentException("Operation " + id + " has a request body that isn't only application/json.");
        return Json.member(content.get("application/json"), "schema");
    }

    // The first 2xx response's JSON schema, if it has one.
    private static Object responseSchema(Object operation) {
        for (var response : Json.members(Json.member(operation, "responses")).entrySet()) {
            if (!response.getKey().startsWith("2"))
                continue;
            var json = Json.member(Json.member(response.getValue(), "content"), "application/json");
            return Json.has(json, "schema") ? Json.member(json, "schema") : null;
        }
        return null;
    }
}
