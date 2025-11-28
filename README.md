# SwiftPGP

Swift implementation of OpenPGP protocol for iOS and macOS. This is a Swift translation of the ObjectivePGP library.

## Status

⚠️ **Work in Progress** - This is an initial translation from Objective-C to Swift. Many features are still being implemented.

## Features

- ✅ Basic type definitions and enums
- ✅ Key and Keyring classes
- ✅ ASCII Armor support
- ✅ Basic structure for encryption/decryption
- ⏳ Packet parsing (in progress)
- ⏳ Full encryption/decryption implementation
- ⏳ Signing and verification
- ⏳ Key generation

## Installation

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: [
    .package(path: "../swiftPGP")
]
```

Or add it via Xcode:
1. File → Add Packages...
2. Enter the path to swiftPGP
3. Select the SwiftPGP library

## Usage

### Import

```swift
import SwiftPGP
```

### Read Keys

```swift
let keys = try SwiftPGP.readKeys(fromPath: "/path/to/key.asc")
```

### Keyring

```swift
let keyring = SwiftPGP.defaultKeyring
let keyring = PGPKeyring()

let allKeys = keyring.keys
keyring.import(keys: [key])
keyring.delete(keys: [key])

try keyring.import(keyIdentifier: "979E4B03DFFE30C6", fromPath: "/path/to/secring.gpg")
if let key = keyring.findKey("979E4B03DFFE30C6") {
    // key found in keyring
}

let keys = keyring.findKeys("Name <email@example.com>")
```

### Export Keys

```swift
// Write keyring to file
try keyring.export().write(to: URL(fileURLWithPath: "keyring.gpg"))

// Public keys data
let publicKeys = try keyring.exportKeys(of: .public)
```

### ASCII Armor

```swift
let armoredKey = PGPArmor.armored(encryptedData, as: .publicKey)
let binaryData = try PGPArmor.readArmored(armoredString)
```

## Architecture

The library is organized into the following modules:

- **PGPTypes**: All enums, constants, and error types
- **PGPFoundation**: Utility functions
- **PGPKey**: Key representation (public/secret)
- **PGPKeyring**: Key storage and management
- **PGPArmor**: ASCII armor encoding/decoding
- **SwiftPGP**: Main API class

## License

This project maintains the same license as ObjectivePGP:
- Free for non-commercial use (BSD variant)
- Commercial license required for commercial products

## Contributing

Contributions are welcome! Please note that this is a work in progress and many features still need to be implemented.

## Original Project

This is a Swift translation of [ObjectivePGP](https://github.com/krzyzanowskim/ObjectivePGP) by Marcin Krzyżanowski.

