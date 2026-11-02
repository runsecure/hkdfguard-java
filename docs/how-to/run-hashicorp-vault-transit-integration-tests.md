# Run the HashiCorp Vault transit integration tests

`HashiCorpVaultTransitIntegrationTest` in `hkdfguard-keywrapping-hashicorpvault` makes real calls to
a Vault transit secrets engine through `HashiCorpVaultTransitKeyWrapperImpl`. This page runs a Vault
dev server in Docker, provisions two transit keys and a token that may use only them, and runs the
tests from the command line and the IDE.

The other tests in the module use a fake transit engine, served on loopback with the JDK's own HTTP
server and called through the wrapper's real `HttpClient`, and run without any of this. The
integration tests are reported as **skipped**, never passed, until a key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `generateAndWrapAsync` produces a wrapped DEK that reveals to 32 non-zero bytes, both generated in
  Vault (no context) and generated locally and encrypted (with one);
- a DEK wrapped under one context is refused under another, and under none;
- a DEK wrapped under one key is refused by another;
- a tampered wrapped DEK, and an invalid token, are refused;
- a crypto provider can generate and reveal its DEK through the wrapper.

The tests never create, rotate, read or delete a key.

If you already run hkdfguard-dotnet's transit integration tests, you have a server, keys and a
token: skip to [step 3](#3-point-the-tests-at-the-key) and use the same values.

## What you need

- Docker.
- Git Bash (on Windows) or any bash with `curl`, for the provisioning script.
- JDK 25.

## 1. Start a Vault dev server

```bash
docker run -d --name hkdfguard-vault --cap-add=IPC_LOCK -p 127.0.0.1:8200:8200 hashicorp/vault:1.19.0
```

The image's default command is `server -dev`: unsealed, in memory, listening on plain http. Bind it
to `127.0.0.1` as above, never to every interface. The wrapper allows http only on a loopback
address.

Read the root token the server printed:

```bash
docker logs hkdfguard-vault 2>&1 | grep 'Root Token:'
```

A dev server keeps everything in memory, so a restarted container starts empty, with a new root
token. Repeat step 2 after every restart.

> The Vault cache's integration tests (`hkdfguard-cache-hashicorpvault`) can use the same server;
> they read the same `HKDFGUARD_TEST_VAULT_ADDR`, `HKDFGUARD_TEST_VAULT_TOKEN` and
> `HKDFGUARD_TEST_VAULT_CACERT`, but need a token that can read their KV secret.

## 2. Provision the keys and a token

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root token> scripts/provision-vault-transit-test-key.sh
```

The script uses the root token only to provision. It:

1. enables a transit engine at `transit` if nothing is mounted there;
2. creates two `aes256-gcm96` keys, `hkdfguard-test` and `hkdfguard-test-other`;
3. writes the policy `hkdfguard-transit-test`, granting `update` (not `create`) on `encrypt`,
   `decrypt` and `datakey/wrapped` for those two keys only;
4. creates a 24-hour token with only that policy, and prints it.

So the tests run with what a real application would get, not root: they can't create a key by
naming one that doesn't exist, list keys, or touch anything else. Re-running the script is safe; it
keeps the keys and prints a new token.

Point the script only at a dev server. If yours was started with `-dev-tls`, set `VAULT_CACERT` to
its CA first, and use https below.

## 3. Point the tests at the key

The tests read their settings from the environment, else from `vault.test.properties` in the
repository root, next to `mvnw` - this repository's counterpart of hkdfguard-dotnet's
`vault.runsettings`, and the file the Vault cache's integration tests read too:

```properties
# The transit key to wrap under, and a second one for the cross-key test.
HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test
HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200
```

The token is read from the environment only, never from the file, so no credential goes in one.
Set it for the command that runs the tests (step 4).

| Variable | Needed | Meaning |
|---|---|---|
| `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` | Yes | The transit key to wrap under; without it every test is skipped |
| `HKDFGUARD_TEST_VAULT_TOKEN` | Yes (environment only) | A token allowed `update` on that key's `encrypt`, `decrypt` and `datakey/wrapped` |
| `HKDFGUARD_TEST_VAULT_ADDR` | No | Vault's address; default `http://127.0.0.1:8200` |
| `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` | No | A second key, for the cross-key test; that test is skipped without it |
| `HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT` | No | The transit mount; default `transit` |
| `HKDFGUARD_TEST_VAULT_CACERT` | No | The full path of a CA to trust, for a server started with TLS |

- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins.** Set one for a single command, or on a CI
  runner, to override the file, or to run the tests without it.

## 4. Run the tests

From the repository root, in Git Bash, macOS or Linux:

```bash
HKDFGUARD_TEST_VAULT_TOKEN=<token the script printed> \
./mvnw -B -pl hkdfguard-keywrapping-hashicorpvault -am verify
```

In PowerShell:

```powershell
$env:HKDFGUARD_TEST_VAULT_TOKEN = '<token the script printed>'
.\mvnw.cmd -B -pl hkdfguard-keywrapping-hashicorpvault -am verify
```

Without the file, set the other variables the same way. To run just the integration tests, add
`-Dtest=HashiCorpVaultTransitIntegrationTest -Dsurefire.failIfNoSpecifiedTests=false`.

Every test in the class should pass with none skipped:

```text
[INFO] Tests run: 8, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: ... s -- in io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.HashiCorpVaultTransitIntegrationTest
```

In **IntelliJ IDEA** and **VS Code**, the tests find `vault.test.properties` too: they look in the
nearest directory above the working directory that holds `mvnw`. Set `HKDFGUARD_TEST_VAULT_TOKEN`
in the run configuration's environment, and add
`--enable-native-access=ALL-UNNAMED --add-modules=jdk.httpserver` to its **VM options** (IntelliJ)
or `java.test.config`'s `vmArgs` (VS Code).

On a CI runner, start the same container as a service, run the provisioning script with the root
token you gave it (`-e VAULT_DEV_ROOT_TOKEN_ID=...`), and pass the printed token to the test step.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 8 tests skipped | `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` is in neither the environment nor `vault.test.properties` | Step 3: the file must be in the repository root, next to `mvnw` |
| 1 test skipped | `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` isn't set | Set it to `hkdfguard-test-other` |
| `Set HKDFGUARD_TEST_VAULT_TOKEN in the environment` | The token isn't in the test process's environment | Step 4 |
| `403 Forbidden` ... `permission denied` | The token expired (24 hours), or the container restarted and the token is gone | Step 2 again, with the new token |
| `400 Bad Request` ... `encryption key not found` | The container restarted and the keys are gone, or the key name is wrong | Step 2 again |
| `no answer within`, or `ConnectException` | The container isn't running, or isn't on `127.0.0.1:8200` | `docker ps`; `docker start hkdfguard-vault`, then step 2 |
| `must be https` | The address isn't loopback and isn't https | Use `127.0.0.1`, or https with `HKDFGUARD_TEST_VAULT_CACERT` |

## When you're done

```bash
docker rm -f hkdfguard-vault
```

Nothing survives: the server kept its keys, policy and tokens in memory.
