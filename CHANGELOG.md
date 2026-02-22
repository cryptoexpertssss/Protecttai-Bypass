# Changelog

All notable changes to this project will be documented in this file.

## [v1.0-b27] - 2026-02-22
### Fixed
- **App Crash Fix**: Resolved "App not installed" and "Auto-closing" issues by implementing robust `Throwable` catch blocks around all hooks.
- **Safety**: Fixed NullPointerExceptions when hooking methods with primitive return types (boolean/int).
- **LSPosed Compatibility**: Aligned module with LSPosed scoping correctly.

## [v1.0-b26] - 2026-02-22
### Changed
- **Rebranding**: Fully renamed project to `ShekharPAIBypass`.
- **Package Name**: Renamed to `com.sch.pai.bypass`.
- **APK Signing**: Enabled debug signing for release builds to ensure APKs are installable.

## [v1.0-b25] - 2026-02-22
### Added
- **Universal Bypass**: Implemented dynamic signature-based scanning for Protectt.ai RASP SDK.
- **Automation**: Added GitHub Actions for auto-building and auto-releasing on push to main.
- **Naming**: Configured APK name as `ShekharPAIBypass-<tag>.apk`.

## [v1.0] - Initial Release
- Initial implementation for Kotak Neo bypass.
