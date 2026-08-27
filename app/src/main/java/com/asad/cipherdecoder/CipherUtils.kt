package com.asad.cipherdecoder

import java.util.Base64
import kotlin.math.log2

/**
 * Utility object for various cipher and encoding utilities
 */
object CipherUtils {
    
    /**
     * Caesar cipher with configurable rotation
     */
    fun caesarCipher(text: String, shift: Int): String {
        return text.map { c ->
            when {
                c in 'A'..'Z' -> ((c.code - 65 + shift) % 26 + 65).toChar()
                c in 'a'..'z' -> ((c.code - 97 + shift) % 26 + 97).toChar()
                else -> c
            }
        }.joinToString("")
    }
    
    /**
     * Atbash cipher (mirror alphabet substitution)
     */
    fun atbashCipher(text: String): String {
        return text.map { c ->
            when {
                c in 'A'..'Z' -> (90 - (c.code - 65)).toChar()
                c in 'a'..'z' -> (122 - (c.code - 97)).toChar()
                else -> c
            }
        }.joinToString("")
    }
    
    /**
     * ROT13 cipher (special case of Caesar with shift 13)
     */
    fun rot13(text: String): String = caesarCipher(text, 13)
    
    /**
     * Decode Base64 string
     */
    fun decodeBase64(text: String): ByteArray? {
        return try {
            Base64.getDecoder().decode(text)
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Encode bytes to Base64 string
     */
    fun encodeBase64(bytes: ByteArray): String {
        return Base64.getEncoder().encodeToString(bytes)
    }
    
    /**
     * Convert ByteArray to hex string
     */
    fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it.toInt() and 255) }
    }
    
    /**
     * Convert ByteArray to UTF-8 string
     */
    fun ByteArray.toUtf8String(): String {
        return try {
            toString(Charsets.UTF_8)
        } catch (e: Exception) {
            contentToString()
        }
    }
    
    /**
     * Calculate Shannon entropy for randomness analysis
     */
    fun calculateEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val frequency = IntArray(256)
        bytes.forEach { frequency[it.toInt() and 255]++ }
        return frequency.filter { it > 0 }.sumOf { count ->
            val probability = count.toDouble() / bytes.size
            -probability * log2(probability)
        }
    }
    
    /**
     * Calculate printable character ratio
     */
    fun calculatePrintableRatio(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        return bytes.count { byte ->
            val c = byte.toInt() and 255
            c in 32..126 || c in listOf(9, 10, 13)
        }.toDouble() / bytes.size
    }
    
    /**
     * XOR decrypt with all possible keys (0-255)
     */
    fun xorDecryptAll(bytes: ByteArray): List<Triple<Double, Int, ByteArray>> {
        return (0..255).map { key ->
            val decrypted = ByteArray(bytes.size) { i ->
                (bytes[i].toInt() xor key).toByte()
            }
            Triple(calculatePrintableRatio(decrypted), key, decrypted)
        }.sortedByDescending { it.first }
    }
    
    /**
     * Check if text is likely valid UTF-8
     */
    fun isValidUtf8(bytes: ByteArray): Boolean {
        return try {
            bytes.toString(Charsets.UTF_8)
            true
        } catch (e: Exception) {
            false
        }
    }
}
