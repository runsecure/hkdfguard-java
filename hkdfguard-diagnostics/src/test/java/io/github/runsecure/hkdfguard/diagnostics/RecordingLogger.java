package io.github.runsecure.hkdfguard.diagnostics;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.event.LoggingEvent;
import org.slf4j.helpers.LegacyAbstractLogger;
import org.slf4j.helpers.MessageFormatter;
import org.slf4j.spi.LoggingEventAware;

/**
 * An SLF4J logger that records every entry, including the fluent API's key-values and markers.
 * Thread-safe. When disabled, every level reports disabled and nothing is recorded.
 */
final class RecordingLogger extends LegacyAbstractLogger implements LoggingEventAware {
    record Entry(Level level, Integer eventId, String message, Throwable exception, List<Marker> markers) {
    }

    private final List<Entry> entries = new ArrayList<>();
    private final boolean enabled;

    RecordingLogger() {
        this(true);
    }

    RecordingLogger(boolean enabled) {
        this.enabled = enabled;
        this.name = "recording";
    }

    synchronized List<Entry> entries() {
        return List.copyOf(entries);
    }

    @Override
    public synchronized void log(LoggingEvent event) {
        Integer eventId = null;
        if (event.getKeyValuePairs() != null)
            for (var pair : event.getKeyValuePairs())
                if (HkdfGuardLog.EVENT_ID_KEY.equals(pair.key))
                    eventId = (Integer) pair.value;

        var message = MessageFormatter.basicArrayFormat(event.getMessage(), event.getArgumentArray());
        var markers = event.getMarkers() == null ? List.<Marker>of() : List.copyOf(event.getMarkers());
        entries.add(new Entry(event.getLevel(), eventId, message, event.getThrowable(), markers));
    }

    @Override
    protected synchronized void handleNormalizedLoggingCall(Level level, Marker marker, String messagePattern, Object[] arguments, Throwable throwable) {
        var markers = marker == null ? List.<Marker>of() : List.of(marker);
        entries.add(new Entry(level, null, MessageFormatter.basicArrayFormat(messagePattern, arguments), throwable, markers));
    }

    @Override
    protected String getFullyQualifiedCallerName() {
        return null;
    }

    @Override
    public boolean isTraceEnabled() {
        return enabled;
    }

    @Override
    public boolean isDebugEnabled() {
        return enabled;
    }

    @Override
    public boolean isInfoEnabled() {
        return enabled;
    }

    @Override
    public boolean isWarnEnabled() {
        return enabled;
    }

    @Override
    public boolean isErrorEnabled() {
        return enabled;
    }
}
