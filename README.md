# Cipher Image Decoder — Android v2

Native Android app for analyzing handwritten cipher/encoded text from images.

## Features
- Pick an image from the phone
- On-device OCR using Google ML Kit
- Editable OCR transcription
- Base64 decoding
- Hex detection
- Caesar/ROT 0–25
- Atbash
- Reverse
- Single-byte XOR ranking
- Base64 fragment detection
- Entropy and printable-byte analysis
- Save report to Android Downloads

## Build
Open this project in Android Studio and let Gradle sync, then use **Build → Build APK(s)**.

Minimum Android version: Android 7.0 (API 24).

OCR is only an aid; handwritten characters should be manually checked before trusting cryptanalysis results.
