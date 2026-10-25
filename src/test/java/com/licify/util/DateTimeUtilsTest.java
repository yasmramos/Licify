package com.licify.util;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DateTimeUtils}.
 */
class DateTimeUtilsTest {

    // ------------------------------------------------------------------
    // Remaining time helpers (LocalDateTime)
    // ------------------------------------------------------------------

    @Test
    void remainingMillisForFutureDateIsPositive() {
        long millis = DateTimeUtils.getRemainingTimeMillis(LocalDateTime.now().plusDays(1));
        assertTrue(millis > 0);
        assertTrue(Math.abs(millis - 24L * 3600 * 1000) < 60_000);
    }

    @Test
    void remainingHelpersReturnZeroForExpiredDates() {
        LocalDateTime past = LocalDateTime.now().minusDays(5);
        assertEquals(0, DateTimeUtils.getRemainingTimeMillis(past));
        assertEquals(0, DateTimeUtils.getRemainingDays(past));
        assertEquals(0, DateTimeUtils.getRemainingHours(past));
        assertEquals(0, DateTimeUtils.getRemainingMinutes(past));
    }

    @Test
    void remainingUnitsAreComputedCorrectly() {
        LocalDateTime future = LocalDateTime.now().plusDays(10).plusHours(23).plusMinutes(59);
        // ChronoUnit truncates toward zero, so each unit is at least one short of nominal.
        assertTrue(DateTimeUtils.getRemainingDays(future) >= 9, "days");
        assertTrue(DateTimeUtils.getRemainingHours(future) >= 262, "hours");
        assertTrue(DateTimeUtils.getRemainingMinutes(future) >= 15778, "minutes");
    }

    @Test
    void nullInputsThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> DateTimeUtils.getRemainingTimeMillis((LocalDateTime) null));
        assertThrows(IllegalArgumentException.class,
                () -> DateTimeUtils.getRemainingDays((LocalDateTime) null));
        assertThrows(IllegalArgumentException.class,
                () -> DateTimeUtils.getRemainingHours((LocalDateTime) null));
        assertThrows(IllegalArgumentException.class,
                () -> DateTimeUtils.getRemainingMinutes((LocalDateTime) null));
    }

    // ------------------------------------------------------------------
    // Legacy Date overloads
    // ------------------------------------------------------------------

    @Test
    void dateOverloadsDelegateToLocalDateTimeBehavior() {
        Date future = DateTimeUtils.toDate(LocalDateTime.now().plusDays(2).plusHours(23).plusMinutes(59));
        Date past = DateTimeUtils.toDate(LocalDateTime.now().minusDays(2));

        assertTrue(DateTimeUtils.getRemainingTimeMillis(future) > 0);
        assertEquals(0, DateTimeUtils.getRemainingTimeMillis(past));
        assertTrue(DateTimeUtils.getRemainingDays(future) >= 1, "days");
        assertTrue(DateTimeUtils.getRemainingHours(future) >= 70, "hours");
        assertTrue(DateTimeUtils.getRemainingMinutes(future) >= 4258, "minutes");
    }

    @Test
    void dateOverloadsRejectNull() {
        assertThrows(IllegalArgumentException.class,
                () -> DateTimeUtils.getRemainingTimeMillis((Date) null));
        assertThrows(IllegalArgumentException.class,
                () -> DateTimeUtils.getRemainingDays((Date) null));
        assertThrows(IllegalArgumentException.class,
                () -> DateTimeUtils.getRemainingHours((Date) null));
        assertThrows(IllegalArgumentException.class,
                () -> DateTimeUtils.getRemainingMinutes((Date) null));
    }

    // ------------------------------------------------------------------
    // Conversions
    // ------------------------------------------------------------------

    @Test
    void conversionsRoundTripPreserveInstantApproximately() {
        LocalDateTime original = LocalDateTime.now().withNano(0);
        Date asDate = DateTimeUtils.toDate(original);
        LocalDateTime back = DateTimeUtils.toLocalDateTime(asDate);
        assertEquals(original, back);
    }

    @Test
    void conversionsHandleNull() {
        assertNull(DateTimeUtils.toLocalDateTime(null));
        assertNull(DateTimeUtils.toDate(null));
    }

    // ------------------------------------------------------------------
    // Expiration status
    // ------------------------------------------------------------------

    @Test
    void expirationStatusCoversAllBranches() {
        assertEquals("UNKNOWN", DateTimeUtils.getExpirationStatus((LocalDateTime) null));
        assertEquals("EXPIRED", DateTimeUtils.getExpirationStatus(LocalDateTime.now().minusDays(1)));
        assertEquals("TODAY", DateTimeUtils.getExpirationStatus(LocalDateTime.now().plusHours(6)));
        assertEquals("SOON", DateTimeUtils.getExpirationStatus(LocalDateTime.now().plusDays(5)));
        assertEquals("VALID", DateTimeUtils.getExpirationStatus(LocalDateTime.now().plusDays(30)));
    }

    @Test
    void expirationStatusDateOverload() {
        assertEquals("UNKNOWN", DateTimeUtils.getExpirationStatus((Date) null));
        assertEquals("EXPIRED",
                DateTimeUtils.getExpirationStatus(DateTimeUtils.toDate(LocalDateTime.now().minusDays(1))));
        assertEquals("VALID",
                DateTimeUtils.getExpirationStatus(DateTimeUtils.toDate(LocalDateTime.now().plusDays(30))));
    }

    // ------------------------------------------------------------------
    // Formatted remaining time
    // ------------------------------------------------------------------

    @Test
    void formattedRemainingTimeHandlesAllGranularities() {
        assertEquals("No expiration date", DateTimeUtils.getFormattedRemainingTime((LocalDateTime) null));
        assertEquals("Expired", DateTimeUtils.getFormattedRemainingTime(LocalDateTime.now().minusHours(1)));

        String daysText = DateTimeUtils.getFormattedRemainingTime(LocalDateTime.now().plusDays(3));
        assertTrue(daysText.contains("days"), daysText);

        String hoursText = DateTimeUtils.getFormattedRemainingTime(LocalDateTime.now().plusHours(5));
        assertTrue(hoursText.contains("hours"), hoursText);

        String minutesText = DateTimeUtils.getFormattedRemainingTime(LocalDateTime.now().plusMinutes(20));
        assertTrue(minutesText.contains("minutes"), minutesText);

        String secondsText = DateTimeUtils.getFormattedRemainingTime(LocalDateTime.now().plusSeconds(30));
        assertTrue(secondsText.contains("seconds"), secondsText);
    }

    @Test
    void formattedRemainingTimeDateOverload() {
        assertEquals("No expiration date", DateTimeUtils.getFormattedRemainingTime((Date) null));
        assertEquals("Expired",
                DateTimeUtils.getFormattedRemainingTime(DateTimeUtils.toDate(LocalDateTime.now().minusDays(1))));
        assertTrue(DateTimeUtils.getFormattedRemainingTime(
                DateTimeUtils.toDate(LocalDateTime.now().plusDays(2))).contains("days"));
    }

    // ------------------------------------------------------------------
    // isExpired / createExpirationDate
    // ------------------------------------------------------------------

    @Test
    void isExpiredSemantics() {
        assertTrue(DateTimeUtils.isExpired((LocalDateTime) null), "null counts as expired");
        assertTrue(DateTimeUtils.isExpired(LocalDateTime.now().minusSeconds(1)));
        assertFalse(DateTimeUtils.isExpired(LocalDateTime.now().plusMinutes(1)));
    }

    @Test
    void createExpirationDateAddsRequestedDays() {
        LocalDateTime result = DateTimeUtils.createExpirationDate(7);
        // ChronoUnit.DAYS truncates toward zero, so a full 7-day span reads as 6 until it completes.
        assertTrue(DateTimeUtils.getRemainingDays(result) >= 6);
    }

    @Test
    void createExpirationDateWithPrecisionTruncatesSecondsAndNanos() {
        LocalDateTime result = DateTimeUtils.createExpirationDate(1, 2, 3);
        assertEquals(0, result.getSecond());
        assertEquals(0, result.getNano());
        assertTrue(result.isAfter(LocalDateTime.now().plusDays(1).plusHours(2).plusMinutes(2)));
    }
}
