package io.github.runsecure.hkdfguard.keywrapping.v1;

import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.KmsResult;
import java.util.function.IntFunction;

/** A scriptable stand-in for a platform's native KMS library, recording every call. */
final class FakeHkdfGuardKmsLibrary extends AbstractHkdfGuardKmsLibrary {
    int wrapDekStatus = OK;
    int unwrapDekStatus = OK;
    int generateAndWrapDekStatus = OK;

    Integer bytesWrittenOverride;

    byte[] wrapPayloadToEmit;
    byte[] unwrapPayloadToEmit;
    byte[] generateAndWrapPayloadToEmit;

    /** Bytes a failing unwrap leaves in the destination before reporting its status. */
    byte[] unwrapGarbageOnFailure;

    String lastService;
    byte[] lastWrapPlaintext;
    byte[] lastUnwrapWrapped;

    int wrapCallCount;
    int unwrapCallCount;
    int generateAndWrapCallCount;

    int openFileStatus = OK;
    byte[] openFilePayloadToEmit = new byte[132];
    String lastOpenFilePath;
    int openFileCallCount;

    /** When set, answers describeStatus; otherwise the base class (the shared descriptions). */
    IntFunction<String> describe;

    /** What hardenProcess returns. */
    int hardenStatus = OK;
    int hardenCallCount;
    Integer lastHardenFlags;

    /** When set, every call throws this, as a binding whose library failed to load does. */
    RuntimeException throwOnCall;

    int totalCalls() {
        return wrapCallCount + unwrapCallCount + generateAndWrapCallCount + openFileCallCount;
    }

    @Override
    public String describeStatus(int status) {
        return describe == null ? super.describeStatus(status) : describe.apply(status);
    }

    @Override
    public KmsResult wrapDek(String service, byte[] dek, byte[] destination) {
        wrapCallCount++;
        lastService = service;
        lastWrapPlaintext = dek.clone();
        if (throwOnCall != null)
            throw throwOnCall;

        if (wrapDekStatus != OK)
            return new KmsResult(wrapDekStatus, bytesWrittenOverride != null ? bytesWrittenOverride : 0);

        var payload = wrapPayloadToEmit != null ? wrapPayloadToEmit : dek;
        System.arraycopy(payload, 0, destination, 0, payload.length);
        return new KmsResult(OK, bytesWrittenOverride != null ? bytesWrittenOverride : payload.length);
    }

    @Override
    public KmsResult unwrapDek(String service, byte[] wrapped, byte[] destination) {
        unwrapCallCount++;
        lastService = service;
        lastUnwrapWrapped = wrapped.clone();
        if (throwOnCall != null)
            throw throwOnCall;

        if (unwrapDekStatus != OK) {
            if (unwrapGarbageOnFailure != null)
                System.arraycopy(unwrapGarbageOnFailure, 0, destination, 0, unwrapGarbageOnFailure.length);
            return new KmsResult(unwrapDekStatus, bytesWrittenOverride != null ? bytesWrittenOverride : 0);
        }

        var payload = unwrapPayloadToEmit != null ? unwrapPayloadToEmit : wrapped;
        System.arraycopy(payload, 0, destination, 0, payload.length);
        return new KmsResult(OK, bytesWrittenOverride != null ? bytesWrittenOverride : payload.length);
    }

    @Override
    public KmsResult generateAndWrapDek(String service, byte[] destination) {
        generateAndWrapCallCount++;
        lastService = service;
        if (throwOnCall != null)
            throw throwOnCall;

        if (generateAndWrapDekStatus != OK)
            return new KmsResult(generateAndWrapDekStatus, bytesWrittenOverride != null ? bytesWrittenOverride : 0);

        var payload = generateAndWrapPayloadToEmit != null ? generateAndWrapPayloadToEmit : new byte[64];
        System.arraycopy(payload, 0, destination, 0, payload.length);
        return new KmsResult(OK, bytesWrittenOverride != null ? bytesWrittenOverride : payload.length);
    }

    @Override
    public int hardenProcess(int flags) {
        hardenCallCount++;
        lastHardenFlags = flags;
        if (throwOnCall != null)
            throw throwOnCall;
        return hardenStatus;
    }

    @Override
    protected KmsResult openFileRaw(String path, byte[] destination) {
        openFileCallCount++;
        lastOpenFilePath = path;
        if (throwOnCall != null)
            throw throwOnCall;

        if (openFileStatus != OK)
            return new KmsResult(openFileStatus, 0);

        System.arraycopy(openFilePayloadToEmit, 0, destination, 0, openFilePayloadToEmit.length);
        return new KmsResult(OK, openFilePayloadToEmit.length);
    }
}
