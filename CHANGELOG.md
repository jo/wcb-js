# Changelog

## v2.0.0 - Binary default
Don't base64 encode encrypted messages by default.

**Breaking change:**
* `encrypt` and `encrypt-to` do not encode its output as base64 per default anymore
* `decrypt` and `decrypt-from` do not expect its inputs base64 encoded per default anymore

**Feature:**
* `encrypt`, `decrypt`, `encrypt-to` and `decrypt-from` now take an optional parameter `--base64` (or `-b`) to encode/decode message contents as base64

## v1.0.0
Initial release
