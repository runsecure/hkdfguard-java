# Wrap keys with Google Cloud KMS

This page sets up a Google Cloud KMS key as HkdfGuard's KEK and uses it from Java with
`GoogleKmsKeyWrapperImpl`, in place of the native TPM, Secure Enclave or Platform Crypto Provider
KEK.

## How it compares

Cloud KMS works like AWS KMS: one symmetric key, used through `Encrypt` and `Decrypt`, which never
leaves Cloud KMS.

| | AWS KMS | Azure Key Vault | Google Cloud KMS |
|---|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign | One symmetric key |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key | Principals allowed `useToEncrypt` |
| Context binding | Encryption context (AAD) | A context string bound into the signature | A context string bound as AAD |
| New DEKs | Generated inside KMS | Generated in the process, wrapped, then zeroed | Generated in the process, wrapped, then zeroed |

`GoogleKmsKeyWrapperImpl`:

- **Pins the key.** `Decrypt` is always called against the key you configure, and Cloud KMS
  refuses a ciphertext made under any other key.
- **Binds a fixed HkdfGuard label and your context** into every wrapped DEK as additional
  authenticated data (AAD). A ciphertext the same key made for anything else isn't accepted as a
  DEK.
- **Checksums every request and response with CRC32C**, as Google recommends, so data corrupted
  in transit is refused.

A key file belongs to the wrapper type that made it: a Cloud KMS key file can't be read by the AWS
or Azure wrappers. It is byte for byte the .NET `GoogleKmsKeyWrapper`'s, so either reads the other's,
given the same key and context.

## 1. Create the key

Enable the API, then create a key ring and a key whose purpose is **encryption**
(`ENCRYPT_DECRYPT`, algorithm `GOOGLE_SYMMETRIC_ENCRYPTION`):

```bash
gcloud services enable cloudkms.googleapis.com --project my-project

gcloud kms keyrings create myapp --location us-east1 --project my-project
gcloud kms keys create myapp-wrap --keyring myapp --location us-east1 --project my-project \
  --purpose encryption --protection-level hsm \
  --rotation-period 90d --next-rotation-time 2027-01-01T00:00:00Z
```

| Setting | Choose | Why |
|---|---|---|
| Purpose | **Symmetric encrypt/decrypt** | `GoogleKmsKeyWrapperImpl` calls `Encrypt` and `Decrypt`, which only this purpose accepts |
| Protection level | **HSM** (or Software) | HSM keeps the key in a FIPS 140-2 Level 3 module; both work the same here |
| Rotation | Automatic, if you like | A ciphertext names the version that made it, so rotation needs nothing here |
| Location | Where the application runs | Key rings can't be moved or deleted; the name is part of every call |

In the console: **Security**, **Key Management**, **Create key ring**, then **Create key** with
**Purpose: Symmetric encrypt/decrypt**.

> **Security:** destroying a key version makes every DEK wrapped under it, and all data encrypted
> under those DEKs, permanently unrecoverable. Cloud KMS waits before destroying a version (30 days
> by default; `--destroy-scheduled-duration` sets it when the key is created), during which it can
> be restored. Keep every version that made a key file in use enabled.

Copy the key's **resource name**, for example
`projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap`:

```bash
gcloud kms keys describe myapp-wrap --keyring myapp --location us-east1 --project my-project --format "value(name)"
```

Give the key, never a key version (`.../cryptoKeyVersions/1`): the wrapper refuses one. Encrypt
uses the key's primary version, and Decrypt finds the version from the ciphertext.

## 2. Grant each identity only what it calls

Grant roles on the **key**, not the project or key ring:

| Identity | Role on the key |
|---|---|
| Release pipeline that creates key files | Cloud KMS CryptoKey Encrypter (`roles/cloudkms.cryptoKeyEncrypter`) |
| Application | Cloud KMS CryptoKey Decrypter (`roles/cloudkms.cryptoKeyDecrypter`) |

```bash
gcloud kms keys add-iam-policy-binding myapp-wrap --keyring myapp --location us-east1 --project my-project \
  --member "serviceAccount:myapp@my-project.iam.gserviceaccount.com" \
  --role roles/cloudkms.cryptoKeyDecrypter
```

> **Security:** give the application decrypt without encrypt. Symmetric encryption needs no
> secret beyond permission to use the key, so any principal allowed `useToEncrypt` can create a key
> file the application accepts, holding a DEK of its choosing. Keep encrypt with the pipeline.

## 3. Give the process a credential

The client signs in with Application Default Credentials (ADC). Deployed, use the **attached
service account** (Compute Engine, Cloud Run, GKE Workload Identity); outside Google Cloud, use
Workload Identity Federation. On a developer machine, ADC uses
`gcloud auth application-default login`. Don't give a deployed process a service account key file.

## 4. Create the wrapper

Add the artifact, and Google's libraries BOM, which keeps the Cloud KMS client, gax, gRPC and
Protobuf at the versions the wrapper was built against:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.google.cloud</groupId>
      <artifactId>libraries-bom</artifactId>
      <version>26.90.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<dependencies>
  <dependency>
    <groupId>io.github.runsecure</groupId>
    <artifactId>hkdfguard-keywrapping-googlekms</artifactId>
    <version>1.0.0</version>
  </dependency>
</dependencies>
```

> **TODO (maintainer):** confirm the version once the artifact is published.

libraries-bom 26.90.0 pins Guava 33.6.0-jre, which has
[GHSA-xxph-c9ww-hj94](https://github.com/advisories/GHSA-xxph-c9ww-hj94); this build pins
`com.google.guava:guava` to 33.7.2-jre in its own `dependencyManagement`, and so should yours, until
a newer libraries-bom does.

The client brings its own transport, gRPC over a shaded copy of Netty, so there is no HTTP client
to choose. Key files are read through `hkdfguard-securefile`, which checks them with system calls
made through the FFM API, and the gRPC transport loads a native library of its own: run with
`--enable-native-access=ALL-UNNAMED` on the class path, or
`--enable-native-access=io.github.runsecure.hkdfguard.securefile,io.github.runsecure.hkdfguard.platform,io.grpc.netty.shaded`
on the module path, where this module is the automatic module
`io.github.runsecure.hkdfguard.keywrapping.googlekms` (the Cloud KMS client names no module, so
neither does a descriptor here).

```java
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import io.github.runsecure.hkdfguard.keywrapping.googlekms.GoogleKmsKeyWrapperImpl;

var kms = KeyManagementServiceClient.create();   // Application Default Credentials
var wrapper = new GoogleKmsKeyWrapperImpl(kms,
        "projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
        "com.example.myapp");
```

- **The context** is bound into every key file and must be given again, exactly, to reveal it.
  Use one value per application, so a key file made for one can't be used by another that shares
  the key. It isn't secret.
- **Create one client and keep it.** `KeyManagementServiceClient` holds a gRPC channel and threads;
  it is safe to share between threads and wrappers. The wrapper never closes it: close it when
  nothing uses the wrapper any more, a key ring's background refresh included. In Spring, declare
  it as a bean, which Spring closes.
- **Client settings.** Retries, timeouts and the endpoint are the client's:
  `KeyManagementServiceClient.create(KeyManagementServiceSettings.newBuilder()...build())`. By
  default the client retries `UNAVAILABLE` and `DEADLINE_EXCEEDED` for up to 60 seconds before the
  wrapper's future fails.

Use it exactly as any other key wrapper: `new KeyRingBuilder().withKeyWrapper(wrapper)`, with
ephemeral keys or key files, as in [Wrap keys with AWS KMS](use-aws-kms.md#5-build-a-key-ring-with-an-ephemeral-key).

## 5. Create and use key files

The release pipeline creates key files with the wrapper itself, running as the pipeline identity
from step 2:

```java
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
int length = wrapper.generateAndWrapAsync(wrapped).join();
Files.write(Path.of("C:\\HkdfGuardKeys\\myapp\\v1.key"), Arrays.copyOf(wrapped, length));
```

`generateAndWrapAsync` generates the DEK in the pipeline's process, since Cloud KMS has no
"generate data key", and zeroes it once wrapped. To wrap the key of an
`AesGcmPipelineDataProtectorImpl`, use `wrapAsync` as in
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file).

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live),
and pass a `KeyFileTrust` as the wrapper's `keyFileTrust` argument if the pipeline writes key files
as an account of its own.

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `withKeyRefreshInterval`: one `Decrypt` call to
Cloud KMS. See [Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for the
trade-off, and [Cloud KMS pricing](https://cloud.google.com/kms/pricing) for what each operation
and active key version costs: HSM keys cost more than software keys.

## Run the integration tests

`GoogleKmsIntegrationTest` makes real calls. Its tests are reported as skipped, never passed, until
the key is named in `google.test.properties` (or the environment).
[Run the Google Cloud KMS integration tests](run-google-kms-integration-tests.md) sets up a test
key and runs them.

## If something goes wrong

Every failure completes the future with a `CryptographicException`; for a Cloud KMS refusal the
message names the gRPC status and Google's description, and the client's `ApiException` is its
`getCause()`. A failed unwrap zeroes the caller's buffer. Argument errors, a resource name that
isn't one included, throw from the call. Reading a key file fails as described for
[AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `PERMISSION_DENIED` | The identity lacks the role on the key, or the API isn't enabled | Step 2; `gcloud services enable cloudkms.googleapis.com` |
| `NOT_FOUND` | The resource name is wrong | Step 1's `describe` command |
| `INVALID_ARGUMENT: Decryption failed` | The key file was altered, made under another key or context, or by another tool | Restore it; use the same key and context |
| `FAILED_PRECONDITION` | The key version the key file names is disabled or destroyed | Re-enable or restore the version |
| `isn't a Cloud KMS key's resource name` (`IllegalArgumentException`) | The name is malformed, or names a key version | Give `projects/.../cryptoKeys/{key}` |
| `corrupted in transit` | A checksum didn't match | Retry; if it persists, check proxies between the process and Cloud KMS |
| `UNAUTHENTICATED`, or `Your default credentials were not found` (from `KeyManagementServiceClient.create()`) | No credential could be found or get a token | Step 3 |
| `UNAVAILABLE` or `DEADLINE_EXCEEDED` | Cloud KMS couldn't be reached, even after the client's retries | Check the network path to `cloudkms.googleapis.com` |
