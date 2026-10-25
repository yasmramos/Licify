package com.licify.encryption;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link HybridEncryptionResult}.
 */
class HybridEncryptionResultTest {

    @Test
    void constructorExposesBothPayloads() {
        byte[] aesKey = new byte[]{1, 2, 3};
        byte[] data = new byte[]{4, 5, 6, 7};

        HybridEncryptionResult result = new HybridEncryptionResult(aesKey, data);

        assertArrayEquals(aesKey, result.getEncryptedAesKey());
        assertArrayEquals(data, result.getEncryptedData());
    }

    @Test
    void acceptsNullFieldsWithoutThrowing() {
        HybridEncryptionResult result = new HybridEncryptionResult(null, null);
        assertNull(result.getEncryptedAesKey());
        assertNull(result.getEncryptedData());
    }

    @Test
    void declaresExplicitSerialVersionUid() throws Exception {
        // The class implements Serializable with an explicit serialVersionUID.
        java.lang.reflect.Field field = HybridEncryptionResult.class.getDeclaredField("serialVersionUID");
        field.setAccessible(true);
        assertEquals(1L, field.getLong(null));
    }
}
