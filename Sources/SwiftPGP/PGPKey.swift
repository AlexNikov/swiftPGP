//  PGPKey.swift
//  SwiftPGP

import Foundation

/// Public + Private key with the same ID.
public class PGPKey: NSObject, PGPExportable, NSCopying {
    
    public let secretKey: PGPPartialKey?
    public let publicKey: PGPPartialKey?
    
    public var keyID: PGPKeyID? {
        return publicKey?.keyID ?? secretKey?.keyID
    }
    
    public var expirationDate: Date? {
        return publicKey?.expirationDate ?? secretKey?.expirationDate
    }
    
    /// Whether key is secret.
    public var isSecret: Bool {
        return secretKey != nil
    }
    
    /// Whether key is public.
    public var isPublic: Bool {
        return publicKey != nil
    }
    
    /// Whether key is encrypted
    public var isEncryptedWithPassword: Bool {
        return publicKey?.isEncryptedWithPassword == true || secretKey?.isEncryptedWithPassword == true
    }
    
    /// Initialize the key with partial keys
    public init(secretKey: PGPPartialKey? = nil, publicKey: PGPPartialKey? = nil) {
        self.secretKey = secretKey
        self.publicKey = publicKey
        super.init()
    }
    
    /**
     *  Decrypts key.
     *  Warning: It is not good idea to keep decrypted key around
     *
     *  @param passphrase Passphrase
     *
     *  @return Decrypted key, or throws error.
     */
    public func decryptedWithPassphrase(_ passphrase: String) throws -> PGPKey {
        let decryptedSecretKey = try secretKey?.decryptedWithPassphrase(passphrase)
        return PGPKey(secretKey: decryptedSecretKey, publicKey: publicKey)
    }
    
    /**
     *  The binary format.
     *  @discussion If you need ASCII format, you can use `PGPArmor`.
     */
    public func export(keyType: PGPKeyType) throws -> Data {
        switch keyType {
        case .public:
            guard let publicKey = publicKey else {
                throw PGPError.notFound
            }
            return try publicKey.export()
        case .secret:
            guard let secretKey = secretKey else {
                throw PGPError.notFound
            }
            return try secretKey.export()
        }
    }
    
    public func export() throws -> Data {
        // Default export public key
        return try export(keyType: .public)
    }
    
    /**
     *  Adds a UserId to both public and secret keys. The userid is self signed by the key
     *
     *  @param userId format generally name <email@address>
     *  @param passphrase Passphrase
     *
     */
    public func addUserId(_ userId: String, passphraseForKey: ((PGPKey) -> String?)? = nil) {
        let user = PGPUser(userID: userId)
        publicKey?.users.append(user)
        secretKey?.users.append(user)
        // TODO: Self-sign the user ID
    }
    
    /**
     *  Removes a UserId from both public and secret keys.
     *
     *  @param userId should be case sensitive identical to an existing userid on the key.
     *
     */
    public func removeUserId(_ userId: String) {
        publicKey?.users.removeAll { $0.userID == userId }
        secretKey?.users.removeAll { $0.userID == userId }
    }
    
    public func copy(with zone: NSZone? = nil) -> Any {
        let secretKeyCopy = secretKey?.copy() as? PGPPartialKey
        let publicKeyCopy = publicKey?.copy() as? PGPPartialKey
        return PGPKey(secretKey: secretKeyCopy, publicKey: publicKeyCopy)
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? PGPKey else {
            return false
        }
        return PGPFoundation.equalObjects(self.secretKey, other.secretKey) &&
               PGPFoundation.equalObjects(self.publicKey, other.publicKey)
    }
    
    public override var hash: Int {
        var hasher = Hasher()
        hasher.combine(secretKey)
        hasher.combine(publicKey)
        return hasher.finalize()
    }
}

