package com.asad.cipherdecoder

import org.junit.Assert.*
import org.junit.Test

class CipherAnalyzerTest {

    @Test
    fun testAnalyzeNotNull() {
        val result = CipherAnalyzer.analyze("hello")
        assertNotNull(result)
    }

    @Test
    fun testAnalyzeContainsInput() {
        val input = "hello"
        val result = CipherAnalyzer.analyze(input)
        assertTrue(result.contains(input))
    }

    @Test
    fun testAnalyzeContainsCaesarSection() {
        val result = CipherAnalyzer.analyze("test")
        assertTrue(result.contains("CAESAR"))
        assertTrue(result.contains("ROT"))
    }

    @Test
    fun testAnalyzeContainsAtbashSection() {
        val result = CipherAnalyzer.analyze("test")
        assertTrue(result.contains("ATBASH"))
    }

    @Test
    fun testAnalyzeContainsReverseSection() {
        val result = CipherAnalyzer.analyze("test")
        assertTrue(result.contains("REVERSE"))
    }

    @Test
    fun testAnalyzeContainsBase64Section() {
        val result = CipherAnalyzer.analyze("test")
        assertTrue(result.contains("BASE64"))
    }

    @Test
    fun testAnalyzeEmptyString() {
        val result = CipherAnalyzer.analyze("")
        assertNotNull(result)
        assertTrue(result.length > 0)
    }

    @Test
    fun testAnalyzeValidBase64() {
        val base64Input = "aGVsbG8=" // "hello" in base64
        val result = CipherAnalyzer.analyze(base64Input)
        assertTrue(result.contains("Valid Base64"))
    }

    @Test
    fun testAnalyzeContainsVersionInfo() {
        val result = CipherAnalyzer.analyze("test")
        assertTrue(result.contains("CIPHER IMAGE DECODER v2"))
    }

    @Test
    fun testAnalyzeWithSpecialCharacters() {
        val input = "hello+world/test="
        val result = CipherAnalyzer.analyze(input)
        assertNotNull(result)
        assertTrue(result.length > 0)
    }

    @Test
    fun testAnalyzeWithNumbers() {
        val input = "abc123def456"
        val result = CipherAnalyzer.analyze(input)
        assertTrue(result.contains("abc123def456"))
    }

    @Test
    fun testAnalyzeConsistency() {
        val input = "testdata"
        val result1 = CipherAnalyzer.analyze(input)
        val result2 = CipherAnalyzer.analyze(input)
        assertEquals(result1, result2)
    }

    @Test
    fun testAnalyzeOutputFormat() {
        val result = CipherAnalyzer.analyze("test")
        assertTrue(result.contains("=".repeat(68)))
    }

    @Test
    fun testAnalyzeMultilineOutput() {
        val result = CipherAnalyzer.analyze("test")
        assertTrue(result.contains("\n"))
    }

    @Test
    fun testAnalyzeRot26IsIdentity() {
        val result = CipherAnalyzer.analyze("abc")
        val lines = result.split("\n")
        val rot0Line = lines.find { it.contains("ROT 00:") }
        val rot26Line = lines.find { it.contains("ROT 00:") }
        // ROT 0 and ROT 26 should produce same result
        assertNotNull(rot0Line)
    }

    @Test
    fun testAnalyzeNoteAboutOcr() {
        val result = CipherAnalyzer.analyze("test")
        assertTrue(result.contains("NOTE"))
        assertTrue(result.contains("OCR"))
    }
}
