//
//  PGPKeySpec.swift
//  SwiftPGP
//

import Foundation

/// Configuration for key generation
public struct PGPKeySpec {
    public let keyAlgorithm: PGPPublicKeyAlgorithm
    public let keyBitsLength: Int
    public let cipherAlgorithm: PGPSymmetricAlgorithm
    public let hashAlgorithm: PGPHashAlgorithm
    
    public init(keyAlgorithm: PGPPublicKeyAlgorithm = .rsa,
                keyBitsLength: Int = 3072,
                cipherAlgorithm: PGPSymmetricAlgorithm = .aes256,
                hashAlgorithm: PGPHashAlgorithm = .sha256) {
        self.keyAlgorithm = keyAlgorithm
        self.keyBitsLength = keyBitsLength
        self.cipherAlgorithm = cipherAlgorithm
        self.hashAlgorithm = hashAlgorithm
    }
}

