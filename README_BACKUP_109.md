# ShekharPAIBypass
<<<<<<< HEAD

=======
>>>>>>> 5b9cbb28b9343d8f582cf68d8fc282564befd12d
A xposed module to bypass protectt.ai in Kotak Neo

---

> [!CAUTION]
> **Disclaimer**: This project is for educational purposes only. The intention is to highlight the weaknesses of current security solutions and to encourage the development of better, more reliable alternatives. Use this information responsibly. Do NOT use this for malicious intent. I am not responsible for the actions taken by users of this module

## Overview

This repository contains a simple demonstration of how to bypass the Protectt.ai security solution implemented in the Kotak Neo app. Protectt.ai is designed to protect Android applications from various security threats, but it has significant flaws that make it unreliable and easy to bypass.

## Why Protectt.ai is Problematic

- **High Rate of False Positives**: Protectt.ai flags unrooted devices with their flawed LSPosed detection done by checking props.

- **Easily Bypassed**: Protectt.ai can be bypassed with minimal effort.

## Why?

This repository demonstrates a method to bypass Protectt.ai's protection with a single hook, highlighting the problems of this security solution.
The intention behind this project is not malicious; rather, it aims to inform developers of the vulnerabilities within Protectt.ai, encouraging them to enhance and improve the solution.

### Steps to Bypass

1. Download the bypass apk from releases or build it on your own.

2. Run the Kotak Neo app with the hook applied, and see how the Protectt.ai solution is bypassed effortlessly.

## Building the Project

The project is configured for **fully automated releases**:

- **Automatic Releases**: Every time you push code to the `main` branch, GitHub Actions will:
  1. Extract the version (e.g., `1.0`) from `app/build.gradle`.
  2. Create a unique Git tag (e.g., `v1.0-b25`).
  3. Build the APK and rename it to `ShekharPAIBypass-v1.0-b25.apk`.
  4. Create a new [GitHub Release](https://github.com/cryptoexpertssss/Protecttai-Bypass/releases) with the APK attached.
- **Local Build**: You can still build locally using `.\gradlew.bat assembleRelease`.

## Contact
<<<<<<< HEAD

=======
>>>>>>> 5b9cbb28b9343d8f582cf68d8fc282564befd12d
Reach out via GitHub or Telegram if available.
