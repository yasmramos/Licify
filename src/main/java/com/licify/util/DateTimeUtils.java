package com.licify.util;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Utility class for date and time handling, specifically designed for expiration
 * calculations and remaining time computations. Provides methods for working with
 * both modern LocalDateTime and legacy Date objects.
 * 
 * @author Licify
 * @version 1.0
 * @since 2024
 */
public class DateTimeUtils {

    /**
     * Calculates the remaining time in milliseconds until the expiration date.
     * 
     * @param expirationDateTime the expiration date and time (must not be null)
     * @return milliseconds remaining until expiration, 0 if already expired
     * @throws IllegalArgumentException if expirationDateTime is null
     */
    public static long getRemainingTimeMillis(LocalDateTime expirationDateTime) {
        if (expirationDateTime == null) {
            throw new IllegalArgumentException("expirationDateTime cannot be null");
        }
        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(expirationDateTime)) {
            return 0; // Already expired
        }
        return Duration.between(now, expirationDateTime).toMillis();
    }

    /**
     * Calculates the remaining days until the expiration date.
     * 
     * @param expirationDateTime the expiration date and time (must not be null)
     * @return days remaining until expiration, 0 if already expired
     * @throws IllegalArgumentException if expirationDateTime is null
     */
    public static long getRemainingDays(LocalDateTime expirationDateTime) {
        if (expirationDateTime == null) {
            throw new IllegalArgumentException("expirationDateTime cannot be null");
        }
        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(expirationDateTime)) {
            return 0; // Already expired
        }
        return ChronoUnit.DAYS.between(now, expirationDateTime);
    }

    /**
     * Calculates the remaining hours until the expiration date.
     * 
     * @param expirationDateTime the expiration date and time (must not be null)
     * @return hours remaining until expiration, 0 if already expired
     * @throws IllegalArgumentException if expirationDateTime is null
     */
    public static long getRemainingHours(LocalDateTime expirationDateTime) {
        if (expirationDateTime == null) {
            throw new IllegalArgumentException("expirationDateTime cannot be null");
        }
        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(expirationDateTime)) {
            return 0; // Already expired
        }
        return ChronoUnit.HOURS.between(now, expirationDateTime);
    }

    /**
     * Calculates the remaining minutes until the expiration date.
     * 
     * @param expirationDateTime the expiration date and time (must not be null)
     * @return minutes remaining until expiration, 0 if already expired
     * @throws IllegalArgumentException if expirationDateTime is null
     */
    public static long getRemainingMinutes(LocalDateTime expirationDateTime) {
        if (expirationDateTime == null) {
            throw new IllegalArgumentException("expirationDateTime cannot be null");
        }
        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(expirationDateTime)) {
            return 0; // Already expired
        }
        return ChronoUnit.MINUTES.between(now, expirationDateTime);
    }

    // Overloaded methods for Date compatibility

    /**
     * Calculates the remaining time in milliseconds until the expiration date (legacy Date).
     * 
     * @param expirationDate the expiration date (must not be null)
     * @return milliseconds remaining until expiration, 0 if already expired
     * @throws IllegalArgumentException if expirationDate is null
     */
    public static long getRemainingTimeMillis(Date expirationDate) {
        if (expirationDate == null) {
            throw new IllegalArgumentException("expirationDate cannot be null");
        }
        return getRemainingTimeMillis(toLocalDateTime(expirationDate));
    }

    /**
     * Calculates the remaining days until the expiration date (legacy Date).
     * 
     * @param expirationDate the expiration date (must not be null)
     * @return days remaining until expiration, 0 if already expired
     * @throws IllegalArgumentException if expirationDate is null
     */
    public static long getRemainingDays(Date expirationDate) {
        if (expirationDate == null) {
            throw new IllegalArgumentException("expirationDate cannot be null");
        }
        return getRemainingDays(toLocalDateTime(expirationDate));
    }

    /**
     * Calculates the remaining hours until the expiration date (legacy Date).
     * 
     * @param expirationDate the expiration date (must not be null)
     * @return hours remaining until expiration, 0 if already expired
     * @throws IllegalArgumentException if expirationDate is null
     */
    public static long getRemainingHours(Date expirationDate) {
        if (expirationDate == null) {
            throw new IllegalArgumentException("expirationDate cannot be null");
        }
        return getRemainingHours(toLocalDateTime(expirationDate));
    }

    /**
     * Calculates the remaining minutes until the expiration date (legacy Date).
     * 
     * @param expirationDate the expiration date (must not be null)
     * @return minutes remaining until expiration, 0 if already expired
     * @throws IllegalArgumentException if expirationDate is null
     */
    public static long getRemainingMinutes(Date expirationDate) {
        if (expirationDate == null) {
            throw new IllegalArgumentException("expirationDate cannot be null");
        }
        return getRemainingMinutes(toLocalDateTime(expirationDate));
    }

    /**
     * Converts a legacy Date object to LocalDateTime.
     * 
     * @param date the date to convert (can be null)
     * @return corresponding LocalDateTime, or null if input is null
     */
    public static LocalDateTime toLocalDateTime(Date date) {
        if (date == null) {
            return null;
        }
        return date.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }

    /**
     * Converts a LocalDateTime to legacy Date object for backward compatibility.
     * 
     * @param localDateTime the date and time to convert (can be null)
     * @return corresponding Date, or null if input is null
     */
    public static Date toDate(LocalDateTime localDateTime) {
        if (localDateTime == null) {
            return null;
        }
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    /**
     * Gets the expiration status as descriptive text.
     * 
     * @param expirationDateTime the expiration date and time
     * @return "EXPIRED" if already expired, "TODAY" if expires today,
     *         "SOON" if expires in 7 days or less, "VALID" if more than 7 days remaining,
     *         "UNKNOWN" if null
     */
    public static String getExpirationStatus(LocalDateTime expirationDateTime) {
        if (expirationDateTime == null) {
            return "UNKNOWN";
        }

        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(expirationDateTime)) {
            return "EXPIRED";
        }

        long remainingDays = ChronoUnit.DAYS.between(now, expirationDateTime);

        if (remainingDays == 0) {
            return "TODAY";
        } else if (remainingDays <= 7) {
            return "SOON";
        } else {
            return "VALID";
        }
    }

    /**
     * Gets the expiration status as descriptive text (legacy Date).
     * 
     * @param expirationDate the expiration date
     * @return "EXPIRED" if already expired, "TODAY" if expires today,
     *         "SOON" if expires in 7 days or less, "VALID" if more than 7 days remaining,
     *         "UNKNOWN" if null
     */
    public static String getExpirationStatus(Date expirationDate) {
        if (expirationDate == null) {
            return "UNKNOWN";
        }
        return getExpirationStatus(toLocalDateTime(expirationDate));
    }

    /**
     * Gets the remaining time formatted as human-readable text.
     * 
     * @param expirationDateTime the expiration date and time
     * @return formatted text with remaining time (days, hours, minutes, seconds),
     *         "Expired" if already expired, or "No expiration date" if null
     */
    public static String getFormattedRemainingTime(LocalDateTime expirationDateTime) {
        if (expirationDateTime == null) {
            return "No expiration date";
        }

        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(expirationDateTime)) {
            return "Expired";
        }

        Duration duration = Duration.between(now, expirationDateTime);
        long days = duration.toDays();
        long hours = duration.toHours() % 24;
        long minutes = duration.toMinutes() % 60;
        long seconds = duration.getSeconds() % 60;

        if (days > 0) {
            return String.format("%d days, %d hours, %d minutes", days, hours, minutes);
        } else if (hours > 0) {
            return String.format("%d hours, %d minutes, %d seconds", hours, minutes, seconds);
        } else if (minutes > 0) {
            return String.format("%d minutes, %d seconds", minutes, seconds);
        } else {
            return String.format("%d seconds", seconds);
        }
    }

    /**
     * Gets the remaining time formatted as human-readable text (legacy Date).
     * 
     * @param expirationDate the expiration date
     * @return formatted text with remaining time (days, hours, minutes, seconds),
     *         "Expired" if already expired, or "No expiration date" if null
     */
    public static String getFormattedRemainingTime(Date expirationDate) {
        if (expirationDate == null) {
            return "No expiration date";
        }
        return getFormattedRemainingTime(toLocalDateTime(expirationDate));
    }

    // Additional useful methods

    /**
     * Checks if an expiration date has already passed.
     * 
     * @param expirationDateTime the expiration date and time
     * @return true if expired or if null, false if still valid
     */
    public static boolean isExpired(LocalDateTime expirationDateTime) {
        if (expirationDateTime == null) {
            return true;
        }
        return LocalDateTime.now().isAfter(expirationDateTime);
    }

    /**
     * Creates an expiration date from a number of days from now.
     * 
     * @param days number of days until expiration
     * @return LocalDateTime with the calculated expiration date
     */
    public static LocalDateTime createExpirationDate(int days) {
        return LocalDateTime.now().plusDays(days);
    }

    /**
     * Creates an expiration date with hour and minute precision.
     * 
     * @param days number of days until expiration
     * @param hours number of hours until expiration
     * @param minutes number of minutes until expiration
     * @return LocalDateTime with the calculated expiration date
     */
    public static LocalDateTime createExpirationDate(int days, int hours, int minutes) {
        return LocalDateTime.now()
                .plusDays(days)
                .plusHours(hours)
                .plusMinutes(minutes)
                .withSecond(0)
                .withNano(0);
    }
}