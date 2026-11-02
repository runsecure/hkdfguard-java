package io.github.runsecure.hkdfguard.integration.hashicorpvault.generator;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.BiFunction;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

/**
 * Generates hkdfguard-integration-hashicorpvault's typed API from Vault's OpenAPI document: what
 * vault-client-go's generate/templates produce through openapi-generator, in Java - and what the
 * .NET HkdfGuard.Integration.HashiCorpVault.Generator produces in C#. One class per tag (AuthApi,
 * IdentityApi, SecretsApi, SystemApi) with one method per operation (and an overload without
 * options), the VaultApis interface whose methods reach them from a VaultClient, and one model per
 * schema in the schema package.
 * <p>
 * As vault-client-go, operations whose id ends in 2, 3 or 4 (duplicates Vault's spec lists for
 * alternative paths) or starts EnterpriseStub are left out, and so are their schemas.
 * <p>
 * Settings can narrow that further: an "include" list of regular expressions, matched against each
 * operation's name in PascalCase (KvV2Read, AppRoleLogin - the .NET method name without Async).
 * Only operations one of them matches are generated, only the schemas those operations use
 * (directly, or through another schema), and only the classes that still have an operation. Each
 * expression must match at least one operation, so a typo or an operation the spec has dropped is
 * noticed rather than silently generating less.
 */
public final class VaultClientGenerator {
    static final String PACKAGE = "io.github.runsecure.hkdfguard.integration.hashicorpvault";
    static final String SCHEMA_PACKAGE = PACKAGE + ".schema";

    /** Where the runtime package's files go, relative to the output directory. */
    static final String PACKAGE_DIRECTORY = PACKAGE.replace('.', '/');

    // The tags in the order vault-client-go lists them, and what each class holds.
    private static final Map<String, String> KNOWN_TAGS = new LinkedHashMap<>();

    static {
        KNOWN_TAGS.put("auth", "Vault's auth methods and tokens.");
        KNOWN_TAGS.put("identity", "Vault's identity store: entities, groups, aliases, OIDC and MFA.");
        KNOWN_TAGS.put("secrets", "Vault's secrets engines.");
        KNOWN_TAGS.put("system", "Vault's system backend (sys/).");
    }

    // Names generated code uses itself, so a parameter can't take them.
    private static final Set<String> RESERVED_PARAMETER_NAMES = Set.of("options", "request", "requestPath", "query", "client");

    // vault-client-go's .openapi-generator-ignore: model_*2_request.go, ..., model_enterprise_stub*.
    private static final Pattern EXCLUDED_SCHEMA = Pattern.compile("^EnterpriseStub|[234](Request|Response)$");

    private static final Pattern PLACEHOLDER = Pattern.compile("([^{]*)\\{([^}]*)\\}");

    private VaultClientGenerator() {
    }

    /**
     * The generated files for the OpenAPI document openApiJson, by path relative to the output
     * directory ('/'-separated), each with '\n' line endings.
     *
     * @param openApiJson  Vault's OpenAPI document
     * @param settingsJson the generator's settings - {"include": ["^KvV2", ...]} - or null to
     *                     generate every operation vault-client-go does
     * @throws IllegalArgumentException the document uses something the generator doesn't handle,
     *                                  the settings aren't valid, or an include pattern matches no
     *                                  operation
     */
    public static SortedMap<String, String> generate(String openApiJson, String settingsJson) {
        var include = readInclude(settingsJson);
        var spec = OpenApiSpec.read(Json.parse(openApiJson));

        var operations = new ArrayList<OpenApiSpec.Operation>();
        for (var operation : spec.operations()) {
            if (!isExcluded(Java.pascal(operation.id())))
                operations.add(operation);
        }
        if (include != null) {
            for (var pattern : include) {
                if (operations.stream().noneMatch(o -> pattern.matcher(Java.pascal(o.id())).find()))
                    throw new IllegalArgumentException("The include pattern '" + pattern + "' matches no operation.");
            }
            operations.removeIf(o -> include.stream().noneMatch(p -> p.matcher(Java.pascal(o.id())).find()));
        }

        var schemaNames = new TreeSet<String>();
        for (var name : spec.schemas().keySet()) {
            if (!EXCLUDED_SCHEMA.matcher(name).find())
                schemaNames.add(name);
        }

        // Which operations send or return each schema, for its summary and how it's typed.
        var requestUses = new LinkedHashMap<String, List<OpenApiSpec.Operation>>();
        var responseUses = new LinkedHashMap<String, List<OpenApiSpec.Operation>>();
        for (var operation : operations) {
            var requestName = operation.requestSchema() == null ? null : OpenApiSpec.refName(operation.requestSchema());
            if (requestName != null)
                requestUses.computeIfAbsent(requestName, k -> new ArrayList<>()).add(operation);
            var responseName = operation.responseSchema() == null ? null : OpenApiSpec.refName(operation.responseSchema());
            if (responseName != null)
                responseUses.computeIfAbsent(responseName, k -> new ArrayList<>()).add(operation);
        }

        var used = new ArrayList<>(requestUses.keySet());
        used.addAll(responseUses.keySet());
        for (var name : used) {
            if (!schemaNames.contains(name))
                throw new IllegalArgumentException("Schema " + name + " is used by a generated operation but is missing or excluded.");
        }

        // Narrowed, only the schemas the operations use are generated: those they send or return,
        // and those those refer to.
        if (include != null)
            schemaNames = new TreeSet<>(referenced(spec, used));

        var byType = new TreeMap<String, List<String>>();
        for (var name : schemaNames)
            byType.computeIfAbsent(Java.pascal(name), k -> new ArrayList<>()).add(name);
        for (var clash : byType.entrySet()) {
            if (clash.getValue().size() > 1)
                throw new IllegalArgumentException("Schemas " + String.join(", ", clash.getValue()) + " would all be named " + clash.getKey() + ".");
        }

        var files = new TreeMap<String, String>();
        var tags = orderTags(operations.stream().map(OpenApiSpec.Operation::tag).collect(Collectors.toCollection(LinkedHashSet::new)));
        files.put(PACKAGE_DIRECTORY + "/VaultApis.java", apisFile(spec, tags));
        for (var tag : tags) {
            var tagged = operations.stream().filter(o -> o.tag().equals(tag)).toList();
            files.put(PACKAGE_DIRECTORY + "/" + apiClass(tag) + ".java", apiFile(spec, tag, tagged));
        }
        for (var name : schemaNames) {
            files.put(PACKAGE_DIRECTORY + "/schema/" + Java.pascal(name) + ".java", modelFile(spec, name, spec.schemas().get(name),
                    requestUses.getOrDefault(name, List.of()), responseUses.getOrDefault(name, List.of())));
        }

        // Prose from the spec can carry its own line endings.
        files.replaceAll((path, content) -> content.replace("\r\n", "\n").replace('\r', '\n'));
        return files;
    }

    // The settings' include patterns; null without settings or an include list.
    private static List<Pattern> readInclude(String settingsJson) {
        if (settingsJson == null)
            return null;

        Object settings;
        try {
            settings = Json.parse(settingsJson);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The generator's settings aren't JSON: " + e.getMessage(), e);
        }
        if (!(settings instanceof Map<?, ?> map))
            throw new IllegalArgumentException("The generator's settings must be a JSON object.");

        List<Pattern> include = null;
        for (var setting : map.entrySet()) {
            switch ((String) setting.getKey()) {
                case "description" -> {
                }
                case "include" -> {
                    if (!(setting.getValue() instanceof List<?> patterns) || patterns.isEmpty()
                            || !patterns.stream().allMatch(p -> p instanceof String))
                        throw new IllegalArgumentException("The generator's \"include\" setting must be a non-empty array of regular expressions.");
                    include = new ArrayList<>();
                    for (var pattern : patterns) {
                        try {
                            include.add(Pattern.compile((String) pattern));
                        } catch (PatternSyntaxException e) {
                            throw new IllegalArgumentException("An include pattern isn't a regular expression: " + e.getMessage(), e);
                        }
                    }
                }
                default -> throw new IllegalArgumentException("Unknown generator setting '" + setting.getKey()
                        + "': only \"include\" and \"description\" are.");
            }
        }
        return include;
    }

    // roots, and every schema they refer to, however indirectly.
    private static Set<String> referenced(OpenApiSpec spec, List<String> roots) {
        var found = new HashSet<String>();
        var pending = new ArrayDeque<>(roots);
        while (!pending.isEmpty()) {
            var name = pending.pop();
            if (!found.add(name))
                continue;
            if (!spec.schemas().containsKey(name))
                throw new IllegalArgumentException("Schema " + name + " is referred to but missing.");
            references(spec.schemas().get(name), pending);
        }
        return found;
    }

    private static void references(Object element, ArrayDeque<String> found) {
        if (element instanceof Map<?, ?> map) {
            var reference = OpenApiSpec.refName(element);
            if (reference != null) {
                found.push(reference);
                return;
            }
            for (var value : map.values())
                references(value, found);
        } else if (element instanceof List<?> list) {
            for (var value : list)
                references(value, found);
        }
    }

    // vault-client-go's partial_filter_operation.
    private static boolean isExcluded(String operationName) {
        return operationName.endsWith("2") || operationName.endsWith("3") || operationName.endsWith("4")
                || operationName.startsWith("EnterpriseStub");
    }

    private static List<String> orderTags(Set<String> tags) {
        var ordered = new ArrayList<String>();
        for (var known : KNOWN_TAGS.keySet()) {
            if (tags.contains(known))
                ordered.add(known);
        }
        tags.stream().filter(t -> !KNOWN_TAGS.containsKey(t)).sorted().forEach(ordered::add);
        return ordered;
    }

    static String apiClass(String tag) {
        return Java.pascal(tag) + "Api";
    }

    // auth(), secrets(): the VaultApis method reaching tag's class.
    private static String apiAccessor(String tag) {
        return Java.camel(tag);
    }

    static String methodName(OpenApiSpec.Operation operation) {
        var pascal = Java.pascal(operation.id());
        return (pascal.charAt(0) == '_' ? pascal : Character.toLowerCase(pascal.charAt(0)) + pascal.substring(1)) + "Async";
    }

    private static String tagSummary(String tag) {
        var summary = KNOWN_TAGS.get(tag);
        return summary != null ? summary : "Vault's \"" + tag + "\" endpoints.";
    }

    private static String header(OpenApiSpec spec) {
        return "// Generated by hkdfguard-integration-hashicorpvault-generator from openapi.json (HashiCorp Vault API " + spec.apiVersion() + ").\n"
                + "// Don't edit: change the generator or the spec, and regenerate (docs/how-to/use-hashicorp-vault-client.md).\n\n";
    }

    private static String apisFile(OpenApiSpec spec, List<String> tags) {
        var code = new StringBuilder(header(spec));
        code.append("package ").append(PACKAGE).append(";\n\n");
        code.append("/** The typed groups of Vault's API a {@link VaultClient} reaches, generated from Vault's OpenAPI spec. */\n");
        code.append("public sealed interface VaultApis permits VaultClient {\n");
        for (var i = 0; i < tags.size(); i++) {
            var tag = tags.get(i);
            if (i > 0)
                code.append('\n');
            code.append("    /**\n");
            code.append("     * ").append(Java.doc(tagSummary(tag))).append('\n');
            code.append("     *\n");
            code.append("     * @return the ").append(Java.doc(tag)).append(" endpoints, through this client\n");
            code.append("     */\n");
            code.append("    default ").append(apiClass(tag)).append(' ').append(apiAccessor(tag)).append("() {\n");
            code.append("        return new ").append(apiClass(tag)).append("((VaultClient) this);\n");
            code.append("    }\n");
        }
        return code.append("}\n").toString();
    }

    private static String apiFile(OpenApiSpec spec, String tag, List<OpenApiSpec.Operation> operations) {
        var type = apiClass(tag);
        var methods = new StringBuilder();
        var schemas = new TreeSet<String>();
        for (var operation : operations)
            methods.append('\n').append(method(operation, schemas));

        var body = methods.toString();
        var imports = new TreeSet<String>();
        for (var schema : schemas)
            imports.add(SCHEMA_PACKAGE + "." + schema);
        if (body.contains("Map."))
            imports.add("java.util.Map");
        if (body.contains("Map<"))
            imports.add("java.util.Map");
        if (body.contains("Objects."))
            imports.add("java.util.Objects");
        imports.add("java.util.concurrent.CompletableFuture");

        var code = new StringBuilder(header(spec));
        code.append("package ").append(PACKAGE).append(";\n\n");
        for (var i : imports)
            code.append("import ").append(i).append(";\n");
        code.append('\n');
        code.append("/** ").append(Java.doc(tagSummary(tag))).append(" Reached through {@link VaultClient#")
                .append(apiAccessor(tag)).append("()}. */\n");
        code.append("public final class ").append(type).append(" {\n");
        code.append("    private final VaultClient client;\n\n");
        code.append("    ").append(type).append("(VaultClient client) {\n");
        code.append("        this.client = client;\n");
        code.append("    }\n");
        code.append(body);
        return code.append("}\n").toString();
    }

    private record Param(OpenApiSpec.Parameter parameter, String name, String type) {
    }

    private static String method(OpenApiSpec.Operation operation, Set<String> schemas) {
        OpenApiSpec.Parameter mount = null;
        var pathParameters = new ArrayList<OpenApiSpec.Parameter>();
        var queryParameters = new ArrayList<OpenApiSpec.Parameter>();
        var lists = false;
        for (var parameter : operation.parameters()) {
            switch (parameter.in()) {
                case "path" -> {
                    if (parameter.isMountPath()) {
                        if (mount == null)
                            mount = parameter;
                    } else {
                        pathParameters.add(parameter);
                    }
                }
                case "query" -> {
                    if (parameter.name().equals("list"))
                        lists = true;
                    else
                        queryParameters.add(parameter);
                }
                default -> throw new IllegalArgumentException("Operation " + operation.id() + " has a " + parameter.in() + " parameter, "
                        + parameter.name() + "; only path and query parameters are handled.");
            }
        }

        // Java names for the parameters, kept clear of each other and of the generated code's own.
        var names = new HashSet<String>();
        var paths = new ArrayList<Param>();
        var queries = new ArrayList<Param>();
        for (var parameter : pathParameters)
            paths.add(param(operation, parameter, names));
        for (var parameter : queryParameters)
            queries.add(param(operation, parameter, names));

        String responseType;
        String reader;
        var responseName = operation.responseSchema() == null ? null : OpenApiSpec.refName(operation.responseSchema());
        if (responseName != null) {
            responseType = Java.pascal(responseName);
            reader = responseType + "::fromJson";
            schemas.add(responseType);
        } else {
            responseType = "Map<String, JsonValue>";
            reader = "JsonValue::readJsonMap";
        }

        String requestType = null;
        if (operation.requestSchema() != null) {
            var requestName = OpenApiSpec.refName(operation.requestSchema());
            if (requestName != null) {
                requestType = Java.pascal(requestName);
                schemas.add(requestType);
            } else if (isFreeForm(operation.requestSchema())) {
                requestType = "Map<String, ?>";
            } else {
                throw new IllegalArgumentException("Operation " + operation.id() + "'s request body is neither a $ref nor a free-form object.");
            }
        }

        var signature = new ArrayList<String>();
        var erased = new ArrayList<String>();
        var arguments = new ArrayList<String>();
        for (var p : paths) {
            signature.add(p.type() + " " + p.name());
            erased.add(p.type());
            arguments.add(p.name());
        }
        if (requestType != null) {
            signature.add(requestType + " request");
            erased.add(requestType.startsWith("Map<") ? "Map" : requestType);
            arguments.add("request");
        }
        for (var q : queries) {
            signature.add(q.type() + " " + q.name());
            erased.add(q.type());
            arguments.add(q.name());
        }

        var description = operation.description();
        var summary = operation.summary() != null ? operation.summary() : description != null ? description : operation.pathDescription();
        if (operation.summary() == null)
            description = null;

        var remarks = new StringBuilder("{@code " + operation.method() + " /v1" + operation.path() + "}");
        if (lists)
            remarks.append(" with {@code list=true}");
        remarks.append('.');
        if (description != null)
            remarks.append(' ').append(Java.doc(description));
        if (operation.unauthenticated())
            remarks.append(" Needs no token.");
        if (operation.sudo())
            remarks.append(" Needs a token with sudo capability.");

        var parameterDocs = new ArrayList<String>();
        for (var p : paths)
            parameterDocs.add("@param " + p.name() + " " + parameterDoc(p.parameter()));
        if (requestType != null)
            parameterDocs.add("@param request The request body.");
        for (var q : queries)
            parameterDocs.add("@param " + q.name() + " " + parameterDoc(q.parameter()));

        String optionsDoc;
        if (mount != null) {
            optionsDoc = "@param options Settings for this request; null for none. Its {@code mountPath} is where the "
                    + (operation.tag().equals("auth") ? "auth method" : "secrets engine") + " is mounted, \""
                    + Java.doc(mountDefault(operation, mount)) + "\" by default.";
        } else {
            optionsDoc = "@param options Settings for this request; null for none.";
        }

        var name = methodName(operation);
        var returnType = "CompletableFuture<VaultResponse<" + responseType + ">>";
        var summaryDoc = Java.doc(summary != null ? summary : operation.method() + " /v1" + operation.path() + ".");
        var fullErased = new ArrayList<>(erased);
        fullErased.add("VaultRequestOptions");

        var code = new StringBuilder();
        // The full overload.
        code.append("    /**\n");
        code.append("     * ").append(summaryDoc).append('\n');
        code.append("     * <p>\n");
        code.append("     * ").append(remarks).append('\n');
        code.append("     *\n");
        for (var doc : parameterDocs)
            code.append("     * ").append(doc).append('\n');
        code.append("     * ").append(optionsDoc).append('\n');
        appendReturnDoc(code, operation);
        code.append("     */\n");
        if (operation.deprecated())
            code.append("    @Deprecated\n");
        var fullSignature = new ArrayList<>(signature);
        fullSignature.add("VaultRequestOptions options");
        code.append("    public ").append(returnType).append(' ').append(name).append('(').append(String.join(", ", fullSignature)).append(") {\n");
        for (var p : paths) {
            if (p.type().equals("String"))
                code.append("        Objects.requireNonNull(").append(p.name()).append(", ").append(Java.literal(p.name())).append(");\n");
        }
        if (requestType != null)
            code.append("        Objects.requireNonNull(request, \"request\");\n");
        for (var q : queries) {
            if (q.type().equals("String"))
                code.append("        Objects.requireNonNull(").append(q.name()).append(", ").append(Java.literal(q.name())).append(");\n");
        }
        code.append("        var requestPath = ").append(pathExpression(operation, mount, paths)).append(";\n");
        code.append("        var query = VaultClient.queryParameters(options);\n");
        if (lists)
            code.append("        query.add(Map.entry(\"list\", \"true\"));\n");
        for (var q : queries) {
            code.append("        query.add(Map.entry(").append(Java.literal(q.parameter().name())).append(", VaultClient.formatQueryValue(")
                    .append(q.name()).append(")));\n");
        }
        code.append("        return client.sendAsync(").append(Java.literal(operation.method())).append(", requestPath, ")
                .append(requestType == null ? "null" : "request").append(", query, options, ").append(reader).append(");\n");
        code.append("    }\n");

        // The overload without options.
        code.append('\n');
        code.append("    /**\n");
        code.append("     * ").append(summaryDoc).append('\n');
        code.append("     * <p>\n");
        code.append("     * As {@link #").append(name).append('(').append(String.join(", ", fullErased)).append(")}, with no options.\n");
        code.append("     *\n");
        for (var doc : parameterDocs)
            code.append("     * ").append(doc).append('\n');
        appendReturnDoc(code, operation);
        code.append("     */\n");
        if (operation.deprecated())
            code.append("    @Deprecated\n");
        var withOptions = new ArrayList<>(arguments);
        withOptions.add("null");
        code.append("    public ").append(returnType).append(' ').append(name).append('(').append(String.join(", ", signature)).append(") {\n");
        code.append("        return ").append(name).append('(').append(String.join(", ", withOptions)).append(");\n");
        code.append("    }\n");
        return code.toString();
    }

    private static void appendReturnDoc(StringBuilder code, OpenApiSpec.Operation operation) {
        code.append("     * @return completes with Vault's response; null if it has no body; fails with\n");
        code.append("     *         {@link VaultResponseException} when Vault refuses the request\n");
        if (operation.deprecated())
            code.append("     * @deprecated Deprecated by Vault.\n");
    }

    private static Param param(OpenApiSpec.Operation operation, OpenApiSpec.Parameter parameter, Set<String> names) {
        var name = Java.camel(parameter.name());
        while (RESERVED_PARAMETER_NAMES.contains(name) || names.contains(name))
            name += "Parameter";
        names.add(name);
        return new Param(parameter, name, parameterType(operation, parameter));
    }

    // "/v1" + the path, its placeholders filled in - each escaped as one segment, the mount path
    // with options' or the default - as vault-client-go's strings.Replace(..., url.PathEscape(...)).
    private static String pathExpression(OpenApiSpec.Operation operation, OpenApiSpec.Parameter mount, List<Param> paths) {
        var parts = new ArrayList<String>();
        var literal = new StringBuilder("/v1");
        var matcher = PLACEHOLDER.matcher(operation.path() + "{}");
        while (matcher.find()) {
            literal.append(matcher.group(1));
            var name = matcher.group(2);
            if (name.isEmpty())
                break;

            if (!literal.isEmpty())
                parts.add(Java.literal(literal.toString()));
            literal.setLength(0);

            if (mount != null && name.equals(mount.name())) {
                parts.add("VaultClient.escapePathSegment(VaultClient.mountPathOr(options, " + Java.literal(mountDefault(operation, mount)) + "))");
                continue;
            }
            var parameter = paths.stream().filter(p -> p.parameter().name().equals(name)).findFirst();
            if (parameter.isEmpty())
                throw new IllegalArgumentException("Operation " + operation.id() + "'s path " + operation.path() + " has a placeholder {"
                        + name + "} with no parameter.");
            parts.add("VaultClient.escapePathSegment(" + parameter.get().name() + ")");
        }

        if (!literal.isEmpty())
            parts.add(Java.literal(literal.toString()));
        return String.join(" + ", parts);
    }

    private static String mountDefault(OpenApiSpec.Operation operation, OpenApiSpec.Parameter mount) {
        var value = Json.string(mount.schema(), "default");
        if (value == null || value.isEmpty())
            throw new IllegalArgumentException("Operation " + operation.id() + "'s mount path parameter " + mount.name() + " has no default.");
        return value;
    }

    private static String parameterType(OpenApiSpec.Operation operation, OpenApiSpec.Parameter parameter) {
        var type = Json.string(parameter.schema(), "type");
        return switch (type == null ? "" : type) {
            case "string" -> "String";
            case "integer" -> "int64".equals(Json.string(parameter.schema(), "format")) ? "long" : "int";
            case "boolean" -> "boolean";
            default -> throw new IllegalArgumentException("Operation " + operation.id() + "'s parameter " + parameter.name() + " is a "
                    + (type == null ? "typeless" : type) + "; only string, integer and boolean are handled.");
        };
    }

    private static String parameterDoc(OpenApiSpec.Parameter parameter) {
        var doc = new StringBuilder(Java.doc(parameter.description() != null
                ? parameter.description()
                : "The " + parameter.name() + " " + parameter.in() + " parameter."));
        // parameterType has already refused a parameter without a schema.
        if (Json.has(parameter.schema(), "default"))
            doc.append(" Vault's default: ").append(Java.doc(Json.write(Json.member(parameter.schema(), "default")))).append('.');
        return doc.toString();
    }

    private static boolean isFreeForm(Object schema) {
        return "object".equals(Json.string(schema, "type")) && !Json.has(schema, "properties");
    }

    /**
     * A property's Java type, and how its value is read from a JsonValue.
     *
     * @param name      the type, as declared
     * @param reference a method reference reading one, or null if reading one takes a lambda
     * @param read      the expression reading one from the JsonValue expression given, at the
     *                  lambda depth given
     */
    private record JavaType(String name, String reference, BiFunction<String, Integer, String> read) {
        static JavaType of(String name, String readMethod) {
            return new JavaType(name, "JsonValue::" + readMethod, (e, d) -> e + "." + readMethod + "()");
        }

        // A function reading one, for readList and readMap.
        String function(int depth) {
            if (reference != null)
                return reference;
            var v = "v" + depth;
            return v + " -> " + read.apply(v, depth + 1);
        }
    }

    private static String modelFile(OpenApiSpec spec, String name, Object schema, List<OpenApiSpec.Operation> sentBy,
            List<OpenApiSpec.Operation> returnedBy) {
        if (!"object".equals(Json.string(schema, "type")))
            throw new IllegalArgumentException("Schema " + name + " isn't an object; only object schemas are handled.");

        // Sent, it's written: free-form values are any object, and required members are required.
        // Returned, it's read: free-form values are JSON, and nothing is relied on being there.
        var isRequest = !sentBy.isEmpty() || (returnedBy.isEmpty() && name.endsWith("Request"));
        // As openapi-generator names models: Vault's spec has a few with underscores.
        var type = Java.pascal(name);
        var required = new HashSet<String>();
        if (Json.member(schema, "required") instanceof List<?> list) {
            for (var r : list)
                required.add((String) r);
        }

        record Property(String jsonName, String accessor, String field, JavaType type, boolean required, boolean deprecated, Object schema) {
        }

        var properties = new ArrayList<Property>();
        var usedAccessors = new HashSet<String>();
        var usedFields = new HashSet<String>();
        for (var member : Json.members(Json.member(schema, "properties")).entrySet()) {
            var accessor = Java.pascal(member.getKey());
            if (accessor.equals(type))
                accessor += "Value";
            if (accessor.equals("Class"))
                accessor = "ClassValue";
            var unique = accessor;
            for (var i = 2; !usedAccessors.add(unique); i++)
                unique = accessor + i;

            // A keyword's "Value" can make two fields one ("default" and "default_value").
            var field = Java.camel(unique);
            var uniqueField = field;
            for (var i = 2; !usedFields.add(uniqueField); i++)
                uniqueField = field + i;
            field = uniqueField;
            properties.add(new Property(member.getKey(), unique, field, typeOf(name + "." + member.getKey(), member.getValue(), isRequest),
                    isRequest && required.contains(member.getKey()), Json.bool(member.getValue(), "deprecated"), member.getValue()));
        }

        var body = new StringBuilder();
        for (var property : properties)
            body.append("    private ").append(property.type().name()).append(' ').append(property.field()).append(";\n");
        if (!properties.isEmpty())
            body.append('\n');

        body.append("    /** An empty model: set what it should hold. */\n");
        body.append("    public ").append(type).append("() {\n");
        body.append("    }\n");

        for (var property : properties) {
            var doc = propertyDoc(property.schema());
            body.append('\n');
            body.append("    /**\n");
            body.append("     * ").append(doc).append('\n');
            body.append("     *\n");
            body.append("     * @return the value; null for none\n");
            if (property.deprecated())
                body.append("     * @deprecated Deprecated by Vault.\n");
            body.append("     */\n");
            if (property.deprecated())
                body.append("    @Deprecated\n");
            body.append("    public ").append(property.type().name()).append(" get").append(property.accessor()).append("() {\n");
            body.append("        return ").append(property.field()).append(";\n");
            body.append("    }\n\n");

            body.append("    /**\n");
            body.append("     * ").append(doc).append('\n');
            body.append("     *\n");
            body.append("     * @param value the value; null for none").append(property.required() ? " (it's required, though)" : "").append('\n');
            body.append("     * @return this model\n");
            if (property.deprecated())
                body.append("     * @deprecated Deprecated by Vault.\n");
            body.append("     */\n");
            if (property.deprecated())
                body.append("    @Deprecated\n");
            body.append("    public ").append(type).append(" set").append(property.accessor()).append('(').append(property.type().name())
                    .append(" value) {\n");
            body.append("        this.").append(property.field()).append(" = value;\n");
            body.append("        return this;\n");
            body.append("    }\n");
        }

        body.append('\n');
        body.append("    @Override\n");
        body.append("    public void writeJson(JsonWriter writer) {\n");
        for (var property : properties) {
            if (property.required()) {
                body.append("        if (this.").append(property.field()).append(" == null)\n");
                body.append("            throw new IllegalStateException(").append(Java.literal(type + "'s " + property.jsonName() + " is required."))
                        .append(");\n");
            }
        }
        body.append("        writer.beginObject();\n");
        for (var property : properties) {
            body.append("        if (this.").append(property.field()).append(" != null)\n");
            body.append("            writer.name(").append(Java.literal(property.jsonName())).append(").value(this.").append(property.field())
                    .append(");\n");
        }
        body.append("        writer.endObject();\n");
        body.append("    }\n\n");

        body.append("    /**\n");
        body.append("     * This model read from json: a JSON object, its members read leniently (see {@link JsonValue}).\n");
        body.append("     *\n");
        body.append("     * @param json the JSON object\n");
        body.append("     * @return the model\n");
        body.append("     * @throws io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultJsonException json isn't an object, or a member\n");
        body.append("     *         isn't what this model holds there\n");
        body.append("     */\n");
        body.append("    public static ").append(type).append(" fromJson(JsonValue json) {\n");
        body.append("        json.requireObject(").append(Java.literal(type)).append(");\n");
        body.append("        var model = new ").append(type).append("();\n");
        for (var property : properties) {
            body.append("        model.").append(property.field()).append(" = ")
                    .append(property.type().read().apply("json.member(" + Java.literal(property.jsonName()) + ")", 0)).append(";\n");
        }
        body.append("        return model;\n");
        body.append("    }\n");

        var text = body.toString();
        var imports = new TreeSet<String>();
        imports.add(PACKAGE + ".JsonValue");
        imports.add(PACKAGE + ".JsonWriter");
        imports.add(PACKAGE + ".VaultModel");
        if (text.contains("OffsetDateTime"))
            imports.add("java.time.OffsetDateTime");
        if (text.contains("List<"))
            imports.add("java.util.List");
        if (text.contains("Map<"))
            imports.add("java.util.Map");

        var code = new StringBuilder(header(spec));
        code.append("package ").append(SCHEMA_PACKAGE).append(";\n\n");
        for (var i : imports)
            code.append("import ").append(i).append(";\n");
        code.append('\n');
        code.append("/** ").append(modelSummary(name, schema, sentBy, returnedBy)).append(" */\n");
        code.append("public final class ").append(type).append(" implements VaultModel {\n");
        code.append(text);
        return code.append("}\n").toString();
    }

    private static String modelSummary(String name, Object schema, List<OpenApiSpec.Operation> sentBy, List<OpenApiSpec.Operation> returnedBy) {
        var description = Json.string(schema, "description");
        if (description != null && !description.isEmpty())
            return Java.doc(description);

        if (!sentBy.isEmpty())
            return "The request body of " + methods(sentBy) + ".";
        if (!returnedBy.isEmpty())
            return "The data " + methods(returnedBy) + " return" + (returnedBy.size() == 1 ? "s" : "") + ".";
        return "The " + Java.doc(name) + " schema.";
    }

    private static String methods(List<OpenApiSpec.Operation> operations) {
        return operations.stream()
                .map(o -> "{@link " + PACKAGE + "." + apiClass(o.tag()) + "#" + methodName(o) + "}")
                .collect(Collectors.joining(", "));
    }

    private static String propertyDoc(Object property) {
        var description = Json.string(property, "description");
        var doc = new StringBuilder(Java.doc(description != null ? description : "Not described by Vault's spec."));

        var remarks = new ArrayList<String>();
        if ("duration".equals(Json.string(property, "format")))
            remarks.add("A duration: seconds, or a Go duration such as \"24h\".");
        if (Json.member(property, "enum") instanceof List<?> values)
            remarks.add("One of: " + values.stream().map(Json::write).collect(Collectors.joining(", ")) + ".");
        if (Json.has(property, "default"))
            remarks.add("Vault's default: " + Json.write(Json.member(property, "default")) + ".");
        if (!remarks.isEmpty())
            doc.append("\n     * <p>\n     * ").append(Java.doc(String.join(" ", remarks)));
        return doc.toString();
    }

    // The Java type a property's schema maps to: vault-client-go's type mapping, but with free-form
    // values as Object (sent) or JsonValue (returned) where Go has interface{}.
    private static JavaType typeOf(String where, Object schema, boolean isRequest) {
        var reference = OpenApiSpec.refName(schema);
        if (reference != null) {
            var model = Java.pascal(reference);
            return new JavaType(model, null, (e, d) -> e + ".readModel(" + model + "::fromJson)");
        }

        var type = Json.string(schema, "type");
        if (type == null)
            return isRequest ? JavaType.of("Object", "readObject") : JavaType.of("JsonValue", "readJson");

        return switch (type) {
            case "string" -> "date-time".equals(Json.string(schema, "format"))
                    ? JavaType.of("OffsetDateTime", "readDateTime")
                    : JavaType.of("String", "readString");
            case "integer" -> "int64".equals(Json.string(schema, "format")) ? JavaType.of("Long", "readLong") : JavaType.of("Integer", "readInteger");
            case "number" -> JavaType.of("Double", "readDouble");
            case "boolean" -> JavaType.of("Boolean", "readBoolean");
            case "array" -> {
                var items = Json.has(schema, "items")
                        ? typeOf(where, Json.member(schema, "items"), isRequest)
                        : isRequest ? JavaType.of("Object", "readObject") : JavaType.of("JsonValue", "readJson");
                yield new JavaType("List<" + items.name() + ">", null, (e, d) -> e + ".readList(" + items.function(d) + ")");
            }
            case "object" -> {
                if (Json.has(schema, "properties"))
                    throw new IllegalArgumentException(where + " is an object with properties of its own; only free-form objects are handled inline.");
                if (Json.member(schema, "additionalProperties") instanceof Map<?, ?> values) {
                    var value = typeOf(where, values, isRequest);
                    yield new JavaType("Map<String, " + value.name() + ">", null, (e, d) -> e + ".readMap(" + value.function(d) + ")");
                }
                yield isRequest
                        ? new JavaType("Map<String, Object>", null, (e, d) -> e + ".readMap(JsonValue::readObject)")
                        : JavaType.of("Map<String, JsonValue>", "readJsonMap");
            }
            default -> throw new IllegalArgumentException(where + " has type '" + type + "', which the generator doesn't handle.");
        };
    }
}
