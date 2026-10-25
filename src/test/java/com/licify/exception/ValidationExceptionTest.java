package com.licify.exception;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ValidationException}.
 */
class ValidationExceptionTest {

    @Test
    void noArgsConstructorCreatesExceptionWithNullMessage() {
        ValidationException ex = new ValidationException();
        assertNull(ex.getMessage());
        assertNull(ex.getCause());
        assertTrue(ex instanceof Exception);
    }

    @Test
    void messageConstructorKeepsMessage() {
        ValidationException ex = new ValidationException("invalid license");
        assertEquals("invalid license", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void messageAndCauseConstructorKeepsBoth() {
        RuntimeException cause = new RuntimeException("root");
        ValidationException ex = new ValidationException("wrapped", cause);
        assertEquals("wrapped", ex.getMessage());
        assertSame(cause, ex.getCause());
    }

    @Test
    void causeOnlyConstructorDerivesMessage() {
        IllegalStateException cause = new IllegalStateException("only cause");
        ValidationException ex = new ValidationException(cause);
        assertSame(cause, ex.getCause());
        // Throwable(cause) uses cause.toString() as the message.
        assertEquals("java.lang.IllegalStateException: only cause", ex.getMessage());
    }

    @Test
    void fullConstructorHonorsSuppressionAndStackTraceFlags() {
        RuntimeException cause = new RuntimeException("root");
        ValidationException ex = new ValidationException("m", cause, false, false);
        assertEquals("m", ex.getMessage());
        assertSame(cause, ex.getCause());
        // Suppression disabled -> getSuppressed must be empty
        assertEquals(0, ex.getSuppressed().length);
        // Stack trace disabled -> no stack trace recorded
        assertEquals(0, ex.getStackTrace().length);
    }
}
