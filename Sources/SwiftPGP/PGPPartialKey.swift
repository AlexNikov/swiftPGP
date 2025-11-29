//
//  PGPPartialKey.swift
//  SwiftPGP
//

import Foundation

/// Single Private or Public key.
public class PGPPartialKey: NSObject, PGPExportable, NSCopying {
    
    public let type: PGPKeyType
    public var primaryKeyPacket: PGPPublicKeyPacket?
    public var users: [PGPUser]
    public var subKeys: [PGPPartialKey] = [] // Simplified - full implementation would use PGPPartialSubKey
    public var directSignatures: [PGPSignaturePacket] = []
    public var revocationSignature: PGPSignaturePacket?
    
    public var isEncryptedWithPassword: Bool {
        if let secretPacket = primaryKeyPacket as? PGPSecretKeyPacket {
            return secretPacket.isEncryptedWithPassphrase
        }
        return false
    }
    
    public var expirationDate: Date? {
        // TODO: Calculate from signatures
        return primaryKeyPacket?.createDate
    }
    
    public var keyID: PGPKeyID? {
        return primaryKeyPacket?.keyID
    }
    
    public var fingerprint: PGPFingerprint? {
        return primaryKeyPacket?.fingerprint
    }
    
    public var primaryUser: PGPUser? {
        return users.first
    }
    
    public init(type: PGPKeyType, primaryKeyPacket: PGPPublicKeyPacket? = nil, users: [PGPUser] = [], subKeys: [PGPPartialKey] = []) {
        self.type = type
        self.primaryKeyPacket = primaryKeyPacket
        self.users = users
        self.subKeys = subKeys
        self.directSignatures = []
        self.revocationSignature = nil
        super.init()
    }
    
    /// Initialize with packets array
    public init?(packets: [PGPPacket]) {
        guard !packets.isEmpty else { return nil }
        
        var primaryPacket: PGPPublicKeyPacket?
        var keyUsers: [PGPUser] = []
        
        // First packet must be Public Key or Secret Key
        if let secretPacket = packets.first as? PGPSecretKeyPacket {
            self.type = .secret
            primaryPacket = secretPacket
        } else if let publicPacket = packets.first as? PGPPublicKeyPacket {
            self.type = .public
            primaryPacket = publicPacket
        } else {
            return nil
        }
        
        // Process other packets
        for i in 1..<packets.count {
            let packet = packets[i]
            if let userPacket = packet as? PGPUserIDPacket {
                let user = PGPUser(userID: userPacket.userID)
                keyUsers.append(user)
            } else if let sigPacket = packet as? PGPSignaturePacket {
                // Check if it's a revocation signature
                if sigPacket.type == .keyRevocation || sigPacket.type == .subkeyRevocation {
                    // Store as revocation signature (simplified - should check which key it revokes)
                    if revocationSignature == nil {
                        revocationSignature = sigPacket
                    }
                } else {
                    // Regular signature
                    directSignatures.append(sigPacket)
                }
            }
            // TODO: Handle Subkeys properly
        }
        
        self.primaryKeyPacket = primaryPacket
        self.users = keyUsers
        self.subKeys = []
        self.directSignatures = []
        self.revocationSignature = nil
        super.init()
    }
    
    public func decryptedWithPassphrase(_ passphrase: String) throws -> PGPPartialKey {
        guard let secretPacket = primaryKeyPacket as? PGPSecretKeyPacket else {
            // Not a secret key, return as-is
            return self
        }
        
        let decryptedPacket = try secretPacket.decryptedWithPassphrase(passphrase)
        
        let decryptedKey = PGPPartialKey(type: type, primaryKeyPacket: decryptedPacket, users: users, subKeys: subKeys)
        decryptedKey.directSignatures = directSignatures
        decryptedKey.revocationSignature = revocationSignature
        return decryptedKey
    }
    
    public func copy(with zone: NSZone? = nil) -> Any {
        // Shallow copy for now, need deep copy for packets
        let copy = PGPPartialKey(type: type, primaryKeyPacket: primaryKeyPacket, users: users, subKeys: subKeys)
        copy.directSignatures = directSignatures
        copy.revocationSignature = revocationSignature
        return copy
    }
    
    public func export() throws -> Data {
        var data = Data()
        
        if let primaryPacket = primaryKeyPacket {
            data.append(try primaryPacket.export())
        }
        
        for user in users {
            let userPacket = PGPUserIDPacket(userID: user.userID)
            data.append(try userPacket.export())
        }
        
        // Export signatures
        for signature in directSignatures {
            data.append(try signature.export())
        }
        
        if let revocation = revocationSignature {
            data.append(try revocation.export())
        }
        
        return data
    }
}
