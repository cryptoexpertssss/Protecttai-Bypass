---
description: How to build the Protectt.ai Bypass application
---

To build the application, follow these steps:

1. **Install JDK**: Ensure you have JDK 17 (or compatible) installed and `JAVA_HOME` set correctly.
2. **Open Terminal**: Navigate to the project root directory.
3. **Run Build Command**:
   - On Windows:
     ```bash
     .\gradlew.bat assembleRelease
     ```
   - On Linux/macOS:
     ```bash
     chmod +x gradlew
     ./gradlew assembleRelease
     ```
4. **Locate APK**: Once the build completes, the signed APK will be available at:
   `app/build/outputs/apk/release/app-release-unsigned.apk`

> [!NOTE]
> For a signed release, you will need to configure a keystore in `app/build.gradle` or sign it manually after building.
