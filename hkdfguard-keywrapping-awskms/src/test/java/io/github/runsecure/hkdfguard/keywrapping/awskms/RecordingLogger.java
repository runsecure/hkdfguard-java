package io.github.runsecure.hkdfguard.keywrapping.awskms;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.event.LoggingEvent;
import org.slf4j.helpers.LegacyAbstractLogger;
import org.slf4j.helpers.MessageFormatter;
import org.slf4j.spi.LoggingEventAware;

/** An SLF4J logger that records every entry, with the fluent API's hkdfguard.event_id. Thread-safe. */
final class RecordingLogger extends LegacyAbstractLogger implements LoggingEventAware {
    private static final long serialVersionUID = 1L;

    record Entry(Level level, Object eventId, String message) {
    }

    private final transient List<Entry> entries = new ArrayList<>();

    RecordingLogger() {
        this.name = "recording";
    }

    synchronized List<Entry> entries() {
        return List.copyOf(entries);
    }

    @Override
    public synchronized void log(LoggingEvent event) {
        Object eventId = null;
        if (event.getKeyValuePairs() != null) {
            for (var pair : event.getKeyValuePairs()) {
                if ("hkdfguard.event_id".equals(pair.key))
                    eventId = pair.value;
            }
        }
        entries.add(new Entry(event.getLevel(), eventId, MessageFormatter.basicArrayFormat(event.getMessage(), event.getArgumentArray())));
    }

    @Override
    protected synchronized void handleNormalizedLoggingCall(Level level, Marker marker, String messagePattern, Object[] arguments, Throwable throwable) {
        entries.add(new Entry(level, null, MessageFormatter.basicArrayFormat(messagePattern, arguments)));
    }

    @Override
    protected String getFullyQualifiedCallerName() {
        return null;
    }

    @Override
    public boolean isTraceEnabled() {
        return true;
    }

    @Override
    public boolean isDebugEnabled() {
        return true;
    }

    @Override
    public boolean isInfoEnabled() {
        return true;
    }

    @Override
    public boolean isWarnEnabled() {
        return true;
    }

    @Override
    public boolean isErrorEnabled() {
        return true;
    }
}
