package com.asad.cipherdecoder

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.Base64

class CipherUtilsTest {

    @Before
    fun setUp() {
        // Test setup if needed
    }

    // Caesar Cipher Tests
    @Test
    fun testCaesarCipherShift0() {
        val input = "hello"
        val result = CipherUtils.caesarCipher(input, 0)
        assertEquals("hello", result)
    }

    @Test
    fun testCaesarCipherShift1() {
        val input = "hello"
        val result = CipherUtils.caesarCipher(input, 1)
        assertEquals("ifmmp", result)
    }

    @Test
    fun testCaesarCipherShift13() {
        val input = "hello"
        val result = CipherUtils.caesarCipher(input, 13)
        assertEquals("uryyb", result)
    }

    @Test
    fun testCaesarCipherUpperCase() {
        val input = "HELLO"
        val result = CipherUtils.caesarCipher(input, 1)
        assertEquals("IFMMP", result)
    }

    @Test
    fun testCaesarCipherWraparound() {
        val input = "xyz"
        val result = CipherUtils.caesarCipher(input, 3)
        assertEquals("abc", result)
    }

    @Test
    fun testCaesarCipherWithSpecialChars() {
        val input = "hello123!@#"
        val result = CipherUtils.caesarCipher(input, 1)
        assertEquals("ifmmp123!@#", result)
    }

    // ROT13 Tests
    @Test
    fun testRot13() {
        val input = "hello"
        val result = CipherUtils.rot13(input)
        assertEquals("uryyb", result)
    }

    @Test
    fun testRot13Twice() {
        val input = "hello"
        val encoded = CipherUtils.rot13(input)
        val decoded = CipherUtils.rot13(encoded)
        assertEquals(input, decoded)
    }

    // Atbash Cipher Tests
    @Test
    fun testAtbashCipher() {
        val input = "abc"
        val result = CipherUtils.atbashCipher(input)
        assertEquals("zyx", result)
    }

    @Test
    fun testAtbashCipherUpperCase() {
        val input = "ABC"
        val result = CipherUtils.atbashCipher(input)
        assertEquals("ZYX", result)
    }

    @Test
    fun testAtbashCipherSymmetric() {
        val input = "hello"
        val encoded = CipherUtils.atbashCipher(input)
        val decoded = CipherUtils.atbashCipher(encoded)
        assertEquals(input, decoded)
    }

    // Base64 Tests
    @Test
    fun testBase64Encode() {
        val input = "hello"
        val result = CipherUtils.encodeBase64(input.toByteArray())
        assertEquals("aGVsbG8=", result)
    }

    @Test
    fun testBase64Decode() {
        val input = "aGVsbG8="
        val result = CipherUtils.decodeBase64(input)
        assertNotNull(result)
        assertEquals("hello", result?.toUtf8String())
    }

    @Test
    fun testBase64DecodeInvalid() {
        val input = "!!!invalid!!!"
        val result = CipherUtils.decodeBase64(input)
        assertNull(result)
    }

    @Test
    fun testBase64RoundTrip() {
        val original = "cipher test data 123!@#"
        val encoded = CipherUtils.encodeBase64(original.toByteArray())
        val decoded = CipherUtils.decodeBase64(encoded)
        assertEquals(original, decoded?.toUtf8String())
    }

    // Hex String Tests
    @Test
    fun testByteArrayToHexString() {
        val bytes = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        val result = bytes.toHexString()
        assertEquals("abcdef", result)
    }

    @Test
    fun testByteArrayToHexStringEmpty() {
        val bytes = byteArrayOf()
        val result = bytes.toHexString()
        assertEquals("", result)
    }

    // UTF-8 String Tests
    @Test
    fun testByteArrayToUtf8String() {
        val bytes = "hello world".toByteArray()
        val result = bytes.toUtf8String()
        assertEquals("hello world", result)
    }

    @Test
    fun testByteArrayToUtf8StringUnicode() {
        val bytes = "café".toByteArray(Charsets.UTF_8)
        val result = bytes.toUtf8String()
        assertEquals("café", result)
    }

    // Entropy Tests
    @Test
    fun testCalculateEntropyEmpty() {
        val bytes = byteArrayOf()
        val result = CipherUtils.calculateEntropy(bytes)
        assertEquals(0.0, result, 0.0)
    }

    @Test
    fun testCalculateEntropyUniform() {
        val bytes = byteArrayOf(0x00, 0xFF)
        val result = CipherUtils.calculateEntropy(bytes)
        assertTrue(result > 0.0)
    }

    @Test
    fun testCalculateEntropyLow() {
        val bytes = ByteArray(100) { 0x41 } // All 'A'
        val result = CipherUtils.calculateEntropy(bytes)
        assertEquals(0.0, result, 0.01)
    }

    // Printable Ratio Tests
    @Test
    fun testCalculatePrintableRatio() {
        val bytes = "hello".toByteArray()
        val result = CipherUtils.calculatePrintableRatio(bytes)
        assertEquals(1.0, result, 0.0)
    }

    @Test
    fun testCalculatePrintableRatioMixed() {
        val bytes = "hello\u0000\u0001\u0002world".toByteArray()
        val result = CipherUtils.calculatePrintableRatio(bytes)
        assertTrue(result in 0.0..1.0)
    }

    // XOR Tests
    @Test
    fun testXorDecryptAll() {
        val original = "hello".toByteArray()
        val key = 42
        val xored = ByteArray(original.size) { i -> (original[i].toInt() xor key).toByte() }
        
        val results = CipherUtils.xorDecryptAll(xored)
        assertFalse(results.isEmpty())
        // Results are sorted by printable ratio, highest first
        assertTrue(results[0].first >= 0.0)
    }

    // UTF-8 Validation Tests
    @Test
    fun testIsValidUtf8True() {
        val bytes = "hello world".toByteArray(Charsets.UTF_8)
        assertTrue(CipherUtils.isValidUtf8(bytes))
    }

    @Test
    fun testIsValidUtf8Unicode() {
        val bytes = "café".toByteArray(Charsets.UTF_8)
        assertTrue(CipherUtils.isValidUtf8(bytes))
    }
}
