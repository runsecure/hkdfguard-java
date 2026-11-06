package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.KvV2ReadMetadataResponse;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.KvV2WriteRequest;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.StandardListResponse;
import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Go durations, the JSON requests are written and responses read with, and how leniently. */
class GoDurationAndJsonTest {
    @ParameterizedTest
    @CsvSource({"0,0", "-0,0", "300ms,300000000", "1.5s,1500000000", ".5s,500000000", "1h30m,5400000000000", "-1m,-60000000000",
        "+2s,2000000000", "1h2m3.5s,3723500000000", "100ns,100", "1us,1000", "1\u00b5s,1000", "1\u03bcs,1000", "2h45m,9900000000000",
        "1.0000000001s,1000000000"})
    void parse_ReadsGoDurations(String value, long nanos) {
        assertEquals(Duration.ofNanos(nanos), GoDuration.parse(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "-", "60", "1x", "s", ".s", "1.2.3s", "1s2", "9999999999999999999999h"})
    void parse_RefusesWhatIsntOne(String value) {
        assertThrows(IllegalArgumentException.class, () -> GoDuration.parse(value));
    }

    @Test
    void parse_HoldsMoreThanATimeSpan() {
        assertEquals(Duration.ofHours(9_999_999_999L), GoDuration.parse("9999999999h"));
    }

    @ParameterizedTest
    @CsvSource({"0,0s", "100,100ns", "1500,1.5\u00b5s", "1500000,1.5ms", "300000000,300ms", "1000000000,1s", "300000000000,5m0s",
        "3723500000000,1h2m3.5s", "3600000000000,1h0m0s", "-60000000000,-1m0s", "1,1ns", "1000000001,1.000000001s"})
    void format_WritesGoDurations(long nanos, String expected) {
        assertEquals(expected, GoDuration.format(Duration.ofNanos(nanos)));
        assertEquals(Duration.ofNanos(nanos), GoDuration.parse(expected));
    }

    // --- JsonValue -----------------------------------------------------------------------------

    @Test
    void aStringProperty_TakesWhateverJsonStandsInItsPlace_AsText() {
        var json = JsonValue.parse("""
                {"token_ttl":768,"token_max_ttl":"24h","token_type":true,"token_period":false,
                 "token_policies":["a",1],"bind_secret_id":true,"token_num_uses":"5","secret_id_ttl":null,
                 "secret_id_bound_cidrs":[{"x":1}],"not_in_the_spec":{"nested":[1]}}
                """);

        assertEquals("768", json.member("token_ttl").readString());
        assertEquals("24h", json.member("token_max_ttl").readString());
        assertEquals("true", json.member("token_type").readString());
        assertEquals("false", json.member("token_period").readString());
        assertEquals(List.of("a", "1"), json.member("token_policies").readList(JsonValue::readString));
        assertEquals(true, json.member("bind_secret_id").readBoolean());
        assertEquals(5, json.member("token_num_uses").readInteger());
        assertNull(json.member("secret_id_ttl").readString());
        assertNull(json.member("missing").readString());
        assertEquals(List.of("{\"x\":1}"), json.member("secret_id_bound_cidrs").readList(JsonValue::readString));
    }

    @Test
    void numbers_AreReadLenientlyButExactly() {
        var json = JsonValue.parse("{\"i\":12,\"f\":1.5,\"e\":1e3,\"s\":\" 7 \",\"big\":9223372036854775808,\"neg\":-4.0,\"int\":2147483648}");

        assertEquals(12L, json.member("i").readLong());
        assertEquals(1000L, json.member("e").readLong());
        assertEquals(7L, json.member("s").readLong());
        assertEquals(-4L, json.member("neg").readLong());
        assertEquals(1.5, json.member("f").readDouble());
        assertEquals(7.0, json.member("s").readDouble());
        assertEquals(12L, json.member("i").readObject());
        assertEquals(new BigDecimal("1.5"), json.member("f").readObject());
        assertEquals(new BigDecimal("9223372036854775808"), json.member("big").asBigDecimal());
        assertThrows(VaultJsonException.class, () -> json.member("f").readLong());
        assertThrows(VaultJsonException.class, () -> json.member("big").readLong());
        assertThrows(VaultJsonException.class, () -> json.member("int").readInteger());
        assertThrows(VaultJsonException.class, () -> JsonValue.of("x").readDouble());
        assertThrows(VaultJsonException.class, () -> JsonValue.parse("true").readLong());
        assertThrows(VaultJsonException.class, () -> JsonValue.parse("[]").readDouble());
    }

    @Test
    void theStrictReaders_RefuseAnotherKind() {
        var json = JsonValue.parse("{\"s\":\"x\",\"n\":3,\"b\":false,\"a\":[1],\"o\":{\"k\":null}}");

        assertEquals("x", json.member("s").asString());
        assertEquals(3, json.member("n").asLong());
        assertEquals(3.0, json.member("n").asDouble());
        assertFalse(json.member("b").asBoolean());
        assertEquals(1, json.member("a").asList().size());
        assertTrue(json.member("o").asMap().get("k").isNull());
        assertEquals(JsonValue.Kind.OBJECT, json.kind());
        assertThrows(VaultJsonException.class, () -> json.member("n").asString());
        assertThrows(VaultJsonException.class, () -> json.member("s").asLong());
        assertThrows(VaultJsonException.class, () -> json.member("s").asBoolean());
        assertThrows(VaultJsonException.class, () -> json.member("s").asMap());
        assertThrows(VaultJsonException.class, () -> json.member("s").asList());
        assertThrows(VaultJsonException.class, () -> json.member("a").readMap(JsonValue::readJson));
        assertThrows(VaultJsonException.class, () -> json.member("o").readList(JsonValue::readJson));
        assertThrows(VaultJsonException.class, () -> json.member("o").readJsonMap().get("k").requireObject("K"));
        assertThrows(UnsupportedOperationException.class, () -> json.asMap().put("x", JsonValue.NULL));
        assertSame(JsonValue.NULL, json.member("s").member("anything"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "\"2024-05-06T07:08:09Z\"|0",
        "\"2024-05-06T07:08:09.5+02:00\"|500000000",
        "\"2024-05-06T07:08:09.123456789Z\"|123456789",
        "\"2024-05-06T07:08:09.123456789\"|123456789"})
    void dateTimes_KeepTheirPrecision(String json, int nanos) {
        var time = JsonValue.parse(json).readDateTime();
        assertEquals(nanos, time.getNano());
        assertEquals(9, time.getSecond());
    }

    @Test
    void aDateTimeWithoutAnOffset_IsUtc() {
        assertEquals(OffsetDateTime.of(2024, 5, 6, 7, 8, 9, 0, ZoneOffset.UTC), JsonValue.parse("\"2024-05-06T07:08:09\"").readDateTime());
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"\"", "null"})
    void anEmptyDateTime_IsNone(String json) {
        assertNull(JsonValue.parse(json).readDateTime());
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"yesterday\"", "12"})
    void aDateTimeThatIsntOne_FailsTheResponse(String json) {
        assertThrows(VaultJsonException.class, () -> JsonValue.parse(json).readDateTime());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{", "{\"a\":}", "[1,]", "01", "{} {}", "nul", "\"\\x\""})
    void malformedJson_IsRefused(String json) {
        assertThrows(VaultJsonException.class, () -> JsonValue.parse(json));
    }

    @Test
    void readObject_IsPlainJava() {
        var value = JsonValue.parse("{\"a\":[1,\"two\",true,null,{\"b\":2.5}]}").readObject();

        var expected = new LinkedHashMap<String, Object>();
        expected.put("a", Arrays.asList(1L, "two", true, null, Map.of("b", new BigDecimal("2.5"))));
        assertEquals(expected, value);
        assertNull(JsonValue.NULL.readObject());
    }

    @Test
    void membersKeepTheirOrder_TheLastOfARepeatedNameWinning() {
        var json = JsonValue.parse("{\"z\":1,\"a\":2,\"z\":3}");
        assertEquals(List.of("z", "a"), new ArrayList<>(json.asMap().keySet()));
        assertEquals(3, json.member("z").asLong());
    }

    @Test
    void toString_IsCompactJson_AndEqualityIsStructural() {
        var text = "{\"s\":\"a\\\"b\\n\u00e9\",\"n\":-1.5e3,\"l\":[true,false,null],\"o\":{}}";
        var json = JsonValue.parse(" " + text + " ");

        assertEquals(text.replace("\\u00e9", "\u00e9"), json.toString());
        assertEquals(json, JsonValue.parse(json.toString()));
        assertEquals(json.hashCode(), JsonValue.parse(text).hashCode());
        assertNotEquals(json, JsonValue.parse("{}"));
        assertEquals("\"x\"", JsonValue.of("x").toString());
        assertEquals("null", JsonValue.NULL.toString());
    }

    @Test
    void readModel_And_ReadJson_PassNullThrough() {
        assertNull(JsonValue.NULL.readModel(StandardListResponse::fromJson));
        assertNull(JsonValue.NULL.readJson());
        assertNull(JsonValue.NULL.readJsonMap());
        assertNull(JsonValue.NULL.readList(JsonValue::readString));
        assertNull(JsonValue.NULL.readMap(JsonValue::readString));
        assertNull(JsonValue.NULL.readBoolean());
        assertNull(JsonValue.NULL.readLong());
        assertNull(JsonValue.NULL.readInteger());
        assertNull(JsonValue.NULL.readDouble());
        var json = JsonValue.of("x");
        assertSame(json, json.readJson());
    }

    @Test
    void aGeneratedModel_IsReadLeniently_AndRefusesWhatIsntAnObject() {
        var json = JsonValue.parse("""
                {"cas_required":false,"created_time":"2024-01-01T00:00:00.000000001Z","current_version":"3",
                 "custom_metadata":{"owner":"me"},"delete_version_after":3600,"max_versions":0,"versions":{"1":{"destroyed":false}}}
                """);

        var metadata = KvV2ReadMetadataResponse.fromJson(json);

        assertEquals(false, metadata.getCasRequired());
        assertEquals(1, metadata.getCreatedTime().getNano());
        assertEquals(3L, metadata.getCurrentVersion());
        assertEquals("me", metadata.getCustomMetadata().get("owner").asString());
        assertEquals("3600", metadata.getDeleteVersionAfter());
        assertEquals(0L, metadata.getMaxVersions());
        assertNull(metadata.getOldestVersion());
        assertFalse(metadata.getVersions().get("1").member("destroyed").asBoolean());
        assertThrows(VaultJsonException.class, () -> KvV2ReadMetadataResponse.fromJson(JsonValue.parse("[]")));
    }

    // --- JsonWriter ------------------------------------------------------------------------------

    private static String write(Object value) {
        var buffer = new SecureBuffer();
        new JsonWriter(buffer).value(value);
        return new String(buffer.array(), 0, buffer.length(), StandardCharsets.UTF_8);
    }

    @Test
    void writing_EscapesWhatJsonMust_AndWritesTheRestAsUtf8() {
        assertEquals("\"q\\\"b\\\\n\\n\\r\\t\\b\\f\\u0001\\u001f/\u00e9\u20ac\ud83d\ude00\"", write("q\"b\\n\n\r\t\b\f\u0001\u001f/\u00e9\u20ac\ud83d\ude00"));
        assertArrayEquals("\"\u00e9\ud83d\ude00\"".getBytes(StandardCharsets.UTF_8), write("\u00e9\ud83d\ude00").getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void writing_RefusesAnUnpairedSurrogate() {
        assertThrows(IllegalArgumentException.class, () -> write("\ud83d"));
        assertThrows(IllegalArgumentException.class, () -> write("\ude00x"));
        assertThrows(IllegalArgumentException.class, () -> write(new char[] {'a', '\ud83d'}));
    }

    @Test
    void aCharArray_IsWrittenAsAString() {
        assertEquals("{\"password\":\"s3\\\"cret\"}", write(Map.of("password", "s3\"cret".toCharArray())));
    }

    @Test
    void writing_TakesEveryKindOfValue() {
        var map = new LinkedHashMap<String, Object>();
        map.put("null", null);
        map.put("bool", false);
        map.put("int", 1);
        map.put("long", -2L);
        map.put("short", (short) 3);
        map.put("byte", (byte) 4);
        map.put("big", new BigInteger("123456789012345678901234567890"));
        map.put("decimal", new BigDecimal("1.25"));
        map.put("double", 2.5);
        map.put("whole double", 3.0);
        map.put("float", 0.5f);
        map.put("time", OffsetDateTime.of(2024, 5, 6, 7, 8, 9, 0, ZoneOffset.UTC));
        map.put("token", new StaticVaultToken("protected-form"));
        map.put("list", List.of(1, "a"));
        map.put("array", new Object[] {true});
        map.put("json", JsonValue.parse("{\"k\":[null]}"));
        map.put("model", new KvV2WriteRequest().setData(Map.of("k", "v")));
        map.put(null, "null key");

        assertEquals("{\"null\":null,\"bool\":false,\"int\":1,\"long\":-2,\"short\":3,\"byte\":4,\"big\":123456789012345678901234567890,"
                + "\"decimal\":1.25,\"double\":2.5,\"whole double\":3,\"float\":0.5,\"time\":\"2024-05-06T07:08:09Z\",\"token\":\"protected-form\","
                + "\"list\":[1,\"a\"],\"array\":[true],\"json\":{\"k\":[null]},\"model\":{\"data\":{\"k\":\"v\"}},\"null\":\"null key\"}", write(map));
    }

    @Test
    void writing_RefusesWhatJsonCantHold() {
        assertThrows(IllegalArgumentException.class, () -> write(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> write(Float.POSITIVE_INFINITY));
        assertThrows(IllegalArgumentException.class, () -> write(new Object()));
        assertThrows(IllegalArgumentException.class, () -> write(Duration.ZERO));
    }

    @Test
    void writing_RefusesNestingDeeperThan64() {
        Object nested = "leaf";
        for (var i = 0; i < 64; i++)
            nested = List.of(nested);
        assertEquals(64, write(nested).chars().filter(c -> c == '[').count());

        var tooDeep = List.of(nested);
        assertThrows(IllegalArgumentException.class, () -> write(tooDeep));

        var cyclic = new ArrayList<Object>();
        cyclic.add(cyclic);
        assertThrows(IllegalArgumentException.class, () -> write(cyclic));
    }

    @Test
    void writing_KeepsToTheGrammar() {
        var writer = new JsonWriter(new SecureBuffer());
        assertThrows(IllegalStateException.class, () -> writer.name("top-level"));
        writer.beginObject();
        assertThrows(IllegalStateException.class, () -> writer.value("no name"));
        assertThrows(IllegalStateException.class, writer::endArray);
        writer.name("a");
        assertThrows(IllegalStateException.class, () -> writer.name("b"));
        assertThrows(IllegalStateException.class, writer::endObject);
        assertThrows(NullPointerException.class, () -> new JsonWriter(new SecureBuffer()).beginObject().name(null));
    }

    @Test
    void aRequiredMemberLeftUnset_FailsTheWrite() {
        var e = assertThrows(IllegalStateException.class,
                () -> write(new io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.TransitSetCertificateForKeyRequest()));
        assertTrue(e.getMessage().contains("certificate_chain"), e.getMessage());
    }

    // --- SecureBuffer -----------------------------------------------------------------------------

    @Test
    void secureBuffer_Grows_AndIsZeroedWhenItGrowsAndWhenClosed() throws Exception {
        var buffer = new SecureBuffer(4);
        var first = buffer.array();
        buffer.write("0123456789".getBytes(StandardCharsets.US_ASCII), 0, 10);
        buffer.readFrom(new ByteArrayInputStream(new byte[100_000]));
        var grown = buffer.array();

        assertEquals(100_010, buffer.length());
        assertEquals("0123456789", new String(grown, 0, 10, StandardCharsets.US_ASCII));
        if (first != grown)
            assertTrue(isZero(first));

        buffer.close();
        assertTrue(isZero(grown));
        assertEquals(0, buffer.length());
        assertEquals(1024 * 1024, new SecureBuffer(Long.MAX_VALUE).array().length);
        assertEquals(256, new SecureBuffer(-5).array().length);
    }

    private static boolean isZero(byte[] bytes) {
        for (var b : bytes) {
            if (b != 0)
                return false;
        }
        return true;
    }

    // --- VaultResponseReader --------------------------------------------------------------------

    @Test
    void tokensInAResponse_AreProtectedFromItsBytes_AndAppearNowhereElse() {
        var protector = TestRings.protector();
        var body = """
                {"data":{"note":"kept"},"auth":{"client_token":"hvs.client-secret","accessor":"acc"},
                 "wrap_info":{"token":"hvs.wrapping-secret","ttl":"60"}}
                """.getBytes(StandardCharsets.UTF_8);

        var response = VaultResponseReader.read(body, body.length, protector, JsonValue::readJsonMap);

        assertEquals("hvs.client-secret", TestRings.decrypt(protector, response.auth().clientToken().toString()));
        assertEquals("hvs.wrapping-secret", TestRings.decrypt(protector, response.wrapInfo().token().toString()));
        assertEquals(60, response.wrapInfo().ttl());
        assertEquals("kept", response.data().get("note").asString());
        assertFalse(response.toString().contains("client-secret"), response.toString());
        assertFalse(response.toString().contains("wrapping-secret"), response.toString());
    }

    @Test
    void aBodyWithoutAnEnvelopeMember_IsReadWholeAsData() {
        var body = "{\"initialized\":true,\"auth_like\":{\"client_token\":\"x\"}}".getBytes(StandardCharsets.UTF_8);

        var response = VaultResponseReader.read(body, body.length, TestRings.protector(), JsonValue::readJsonMap);

        assertTrue(response.data().get("initialized").asBoolean());
        assertNull(response.auth());
        assertNull(VaultResponseReader.read(new byte[0], 0, TestRings.protector(), JsonValue::readJsonMap));
        assertNull(VaultResponseReader.read("null".getBytes(StandardCharsets.UTF_8), 4, TestRings.protector(), JsonValue::readJsonMap).data());
    }

    @Test
    void aResponseReadsOnlyTheLengthGiven() {
        var body = "{\"data\":{\"k\":1}}GARBAGE".getBytes(StandardCharsets.UTF_8);
        assertEquals(1, VaultResponseReader.read(body, body.length - 7, TestRings.protector(), JsonValue::readJsonMap).data().get("k").asLong());
    }

    @Test
    void anEnvelopeOfTheWrongShape_FailsTheResponse() {
        for (var text : new String[] {"{\"data\":{},\"wrap_info\":3}", "{\"data\":[]}", "{\"data\":{},\"warnings\":\"w\"}", "{\"data\":{}} {}"}) {
            var body = text.getBytes(StandardCharsets.UTF_8);
            assertThrows(VaultJsonException.class, () -> VaultResponseReader.read(body, body.length, TestRings.protector(), JsonValue::readJsonMap), text);
        }
    }
}
