//
//  PGPIntegrationTests.swift
//  SwiftPGPTests
//

import XCTest
import SwiftPGP

class PGPIntegrationTests: XCTestCase {
    
    func testFullCycle() throws {
        // 1. Generate Keys for Alice and Bob
        let keyGen = PGPKeyGenerator()
        
        guard let aliceKey = keyGen.generate(for: "Alice <alice@example.com>", passphrase: "alice-password") else {
            XCTFail("Failed to generate Alice's key")
            return
        }
        
        guard let bobKey = keyGen.generate(for: "Bob <bob@example.com>", passphrase: nil) else {
            XCTFail("Failed to generate Bob's key")
            return
        }
        
        // 2. Alice encrypts a message for Bob
        let message = "Hello Bob, this is a secret message from Alice!".data(using: .utf8)!
        
        let encryptedData = try SwiftPGP.encrypt(message,
                                                addSignature: true,
                                                using: [bobKey], // Encrypt for Bob
                                                passphraseForKey: { key in
                                                    // Alice needs to sign, so she needs her private key passphrase
                                                    if key.keyID == aliceKey.keyID {
                                                        return "alice-password"
                                                    }
                                                    return nil
                                                })
        
        XCTAssertFalse(encryptedData.isEmpty)
        
        // 3. Bob decrypts the message
        // Bob needs his private key (no passphrase)
        let decryptedData = try SwiftPGP.decrypt(encryptedData,
                                                andVerifySignature: true,
                                                using: [bobKey, aliceKey], // Bob's key to decrypt, Alice's public key to verify signature
                                                passphraseForKey: nil)
        
        let decryptedMessage = String(data: decryptedData, encoding: .utf8)
        XCTAssertEqual(decryptedMessage, "Hello Bob, this is a secret message from Alice!")
        
        // 4. Verify Bob received the message
        print("Successfully decrypted message: \(decryptedMessage ?? "")")
    }
    
    func testKeyGenerationAndExport() throws {
        let keyGen = PGPKeyGenerator()
        guard let key = keyGen.generate(for: "Test User <test@example.com>", passphrase: "password") else {
            XCTFail("Key generation failed")
            return
        }
        
        // Check key structure
        XCTAssertNotNil(key.publicKey)
        XCTAssertNotNil(key.secretKey)
        XCTAssertEqual(key.users.first?.userID, "Test User <test@example.com>")
        
        // Export Public Key
        let publicKeyData = try key.export(keyType: .public)
        let armoredPublic = PGPArmor.armored(publicKeyData, as: .publicKey)
        XCTAssertTrue(armoredPublic.contains("BEGIN PGP PUBLIC KEY BLOCK"))
        
        // Export Secret Key
        let secretKeyData = try key.export(keyType: .secret)
        let armoredSecret = PGPArmor.armored(secretKeyData, as: .secretKey)
        XCTAssertTrue(armoredSecret.contains("BEGIN PGP PRIVATE KEY BLOCK"))
        
        // Import back
        let importedKeys = try SwiftPGP.readKeys(fromData: publicKeyData)
        XCTAssertEqual(importedKeys.count, 1)
        XCTAssertEqual(importedKeys.first?.keyID, key.keyID)
    }
}

