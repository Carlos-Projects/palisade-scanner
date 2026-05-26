---
title: Palisade Scanner
emoji: 🔍
colorFrom: red
colorTo: gray
sdk: docker
pinned: false
app_port: 8000
fullWidth: true
short_description: Scan any URL for prompt injection, hidden instructions, and adversarial content targeting AI agents
---

# Palisade Scanner 🔍

Scan any web URL for **prompt injection**, **hidden instructions**, and **adversarial content**.

## Usage

Enter a URL and the scanner checks it against 10+ detectors:

- Hidden text (white-on-white, zero font, off-screen)
- Injection patterns (Nova-Rules)
- Metadata and HTML comment payloads
- Base64, hex, and encoded content
- Zero-width character injections
- Steganographic markers
- Entropy anomalies

The API is also available at `/scan` endpoint.
