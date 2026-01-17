# HexInlay

Display function argument names in Hex-Rays decompiled code as inlay hints.

## Overview

HexInlay enhances the Hex-Rays decompiler by showing function argument names directly in the decompiled code as inlay hints. This makes it easier to understand function calls without having to look up parameter names.

## Features

- **Argument name hints**: See function parameter names directly in decompiled code
- **Configurable display modes**:
  - **Show All**: Display all argument names
  - **Hide Some**: Hide hints when the argument name matches the parameter name
  - **Hide More**: Hide hints when argument and parameter names are similar (better readability)
  - **Disabled**: Turn off inlay hints completely

## Usage

### Configuration

Access HexInlay settings through `Edit` → `Plugins` → `HexInlay`. Choose your preferred display mode:

| Mode | Example |
|------|---------|
| Show All | `memmove(dst: this->dst, src: src, len: 10)` |
| Hide Some | `memmove(dst: this->dst, src, len: 10)` |
| Hide More | `memmove(this->dst, src, len: 10)` |

### Compatibility

Requires IDA Pro 9.0 or later with Hex-Rays decompiler support.

Supported platforms:
- Windows (x86-64)
- Linux (x86-64)
- macOS (x86-64, ARM64)
