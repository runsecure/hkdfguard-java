package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.KvV2WriteRequest;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.TokenCreateRequest;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.TransitEncryptRequest;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.TransitSetCertificateForKeyRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The generated methods, end to end against a fake Vault. */
class GeneratedApiTest {
    @Test
    void aGeneratedRead_EscapesThePath_AndUsesTheDefaultOrGivenMount() {
        try (var t = TestClient.create()) {
            t.vault().respond = r -> new FakeVault.Answer(200, "{\"data\":{\"data\":{\"password\":\"s3cret\"},\"metadata\":{\"version\":3}}}");

            var response = await(t.client().secrets().kvV2ReadAsync("my app/db"));
            await(t.client().secrets().kvV2ReadAsync("x", VaultRequestOptions.builder().mountPath("/my/mount/").build()));
            await(t.client().secrets().kvV2ReadAsync("x", VaultRequestOptions.builder().mountPath("/").build()));

            assertEquals("s3cret", response.data().getData().get("password").asString());
            assertEquals(3, response.data().getMetadata().get("version").asLong());
            assertEquals(List.of("/v1/kv-v2/data/my%20app%2Fdb", "/v1/my%2Fmount/data/x", "/v1/kv-v2/data/x"),
                    t.vault().requests().stream().map(FakeVault.Received::pathAndQuery).toList());
            assertTrue(t.vault().requests().stream().allMatch(r -> r.method().equals("GET")));
        }
    }

    @Test
    void aGeneratedWrite_PostsItsModel_LeavingOutWhatIsntSet() {
        try (var t = TestClient.create()) {
            var data = new LinkedHashMap<String, Object>();
            data.put("password1", "abc123");
            data.put("password2", "correct horse battery staple");
            t.vault().then(200, "{\"data\":{\"version\":1,\"created_time\":\"2024-05-06T07:08:09Z\",\"destroyed\":false}}");

            var written = await(t.client().secrets().kvV2WriteAsync("foo", new KvV2WriteRequest().setData(data).setOptions(Map.of("cas", 0)),
                    VaultRequestOptions.builder().mountPath("secret").build()));

            var request = t.vault().single();
            assertEquals("POST", request.method());
            assertEquals("/v1/secret/data/foo", request.pathAndQuery());
            assertEquals("{\"data\":{\"password1\":\"abc123\",\"password2\":\"correct horse battery staple\"},\"options\":{\"cas\":0}}", request.bodyText());
            assertEquals(1L, written.data().getVersion());
            assertEquals(false, written.data().getDestroyed());
        }
    }

    @Test
    void requiredMembers_AreAlwaysSent_AndTheirAbsenceThrowsFromTheCall() {
        try (var t = TestClient.create()) {
            await(t.client().secrets().transitSetCertificateForKeyAsync("myapp-kek", new TransitSetCertificateForKeyRequest().setCertificateChain("pem")));

            assertEquals("/v1/transit/keys/myapp-kek/set-certificate", t.vault().single().pathAndQuery());
            assertEquals("{\"certificate_chain\":\"pem\"}", t.vault().single().bodyText());
            assertThrows(IllegalStateException.class,
                    () -> t.client().secrets().transitSetCertificateForKeyAsync("myapp-kek", new TransitSetCertificateForKeyRequest()));
            assertEquals(1, t.vault().requests().size());
        }
    }

    @Test
    void aGeneratedList_AddsListTrue_ToTheCallersQuery() {
        try (var t = TestClient.create()) {
            t.vault().then(200, "{\"data\":{\"keys\":[\"a\",\"b/\"]}}");

            var response = await(t.client().secrets().kvV2ListAsync("dir", VaultRequestOptions.builder().queryParameter("after", "a").build()));

            assertEquals(List.of("a", "b/"), response.data().getKeys());
            assertEquals("/v1/kv-v2/metadata/dir/?after=a&list=true", t.vault().single().pathAndQuery());
        }
    }

    @Test
    void aFreeFormBody_IsSentAsItIs() {
        try (var t = TestClient.create()) {
            var body = new LinkedHashMap<String, Object>();
            body.put("text", "hi");
            body.put("n", 1);

            await(t.client().secrets().cubbyholeWriteAsync("note", body));

            assertEquals("/v1/cubbyhole/note", t.vault().single().pathAndQuery());
            assertEquals("{\"text\":\"hi\",\"n\":1}", t.vault().single().bodyText());
        }
    }

    @Test
    void aTransitEncrypt_SendsOnlyWhatsSet() {
        try (var t = TestClient.create()) {
            t.vault().then(200, "{\"data\":{\"ciphertext\":\"vault:v1:abc\",\"key_version\":1}}");

            var response = await(t.client().secrets().transitEncryptAsync("myapp-kek",
                    new TransitEncryptRequest().setPlaintext("c2VjcmV0").setAssociatedData("YWFk")));

            assertEquals("/v1/transit/encrypt/myapp-kek", t.vault().single().pathAndQuery());
            assertEquals("{\"associated_data\":\"YWFk\",\"plaintext\":\"c2VjcmV0\"}", t.vault().single().bodyText());
            assertEquals("vault:v1:abc", response.data().get("ciphertext").asString());
        }
    }

    @Test
    void aTokenCreate_ProtectsTheIssuedToken() {
        try (var t = TestClient.create()) {
            t.vault().then(200, "{\"auth\":{\"client_token\":\"hvs.child\",\"policies\":[\"default\"]}}");

            var created = await(t.client().auth().tokenCreateAsync(new TokenCreateRequest().setPolicies(List.of("default")).setTtl("5m")));

            assertEquals("hvs.child", t.decrypt(created.auth().clientToken()));
            assertEquals("/v1/auth/token/create", t.vault().single().pathAndQuery());
            assertTrue(t.vault().single().bodyText().contains("\"policies\":[\"default\"]"), t.vault().single().bodyText());
        }
    }

    @Test
    void aGeneratedMethod_RefusesNullArguments_SendingNothing() {
        try (var t = TestClient.create()) {
            assertThrows(NullPointerException.class, () -> t.client().secrets().kvV2ReadAsync(null));
            assertThrows(NullPointerException.class, () -> t.client().secrets().kvV2WriteAsync("p", null));
            assertTrue(t.vault().requests().isEmpty());
        }
    }

    @ParameterizedTest
    @CsvSource({"false,false", "true,true"})
    void queryValues_AreFormattedAsGoFormatsThem(boolean value, String expected) {
        assertEquals(expected, VaultClient.formatQueryValue(value));
        assertEquals("12345", VaultClient.formatQueryValue(12345));
        assertEquals("-9", VaultClient.formatQueryValue(-9L));
        assertEquals("str", VaultClient.formatQueryValue("str"));
    }

    @Test
    void escapePathSegment_EscapesAllButUnreserved() {
        assertEquals("aZ09-_.~%2F%20%3F%23%25%C3%A9", VaultClient.escapePathSegment("aZ09-_.~/ ?#%é"));
    }

    @Test
    void mountPathOr_TrimsSlashes_FallingBackToTheDefault() {
        assertEquals("d", VaultClient.mountPathOr(null, "d"));
        assertEquals("d", VaultClient.mountPathOr(VaultRequestOptions.builder().build(), "d"));
        assertEquals("d", VaultClient.mountPathOr(VaultRequestOptions.builder().mountPath("//").build(), "d"));
        assertEquals("a/b", VaultClient.mountPathOr(VaultRequestOptions.builder().mountPath("/a/b/").build(), "d"));
    }

    @Test
    void theApiGroups_ReachThroughTheClient() {
        try (var t = TestClient.create()) {
            await(t.client().system().sealStatusAsync());
            await(t.client().auth().tokenLookUpSelfAsync());
            assertEquals(List.of("/v1/sys/seal-status", "/v1/auth/token/lookup-self"),
                    t.vault().requests().stream().map(FakeVault.Received::pathAndQuery).toList());
        }
    }
}
