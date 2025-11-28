//  PGPKeyring.swift
//  SwiftPGP

import Foundation

/// Keyring - storage for PGP keys
public class PGPKeyring: NSObject, PGPExportable {
    
    /// Keys in keyring.
    public private(set) var keys: [PGPKey]
    
    public override init() {
        self.keys = []
        super.init()
    }
    
    /**
     Import keys. `keys` property is updated after successful import.
     
     @param keys Keys to import.
     */
    public func `import`(keys: [PGPKey]) {
        for key in keys {
            // Add or update key
            if let existingIndex = self.keys.firstIndex(where: { $0.keyID == key.keyID }) {
                self.keys[existingIndex] = key
            } else {
                self.keys.append(key)
            }
        }
    }
    
    /**
     Import key with given identifier
     
     @param identifier Short (8 characters) key identifier to load.
     @param path Path to the file with the keys.
     @return YES on success.
     */
    public func `import`(keyIdentifier: String, fromPath path: String) throws {
        let loadedKeys = try SwiftPGP.readKeys(fromPath: path)
        
        let foundKey = loadedKeys.first { key in
            let publicID = key.publicKey?.keyID
            let secretID = key.secretKey?.keyID
            
            let identifierUpper = keyIdentifier.uppercased()
            return publicID?.shortIdentifier.uppercased() == identifierUpper ||
                   publicID?.longIdentifier.uppercased() == identifierUpper ||
                   secretID?.shortIdentifier.uppercased() == identifierUpper ||
                   secretID?.longIdentifier.uppercased() == identifierUpper
        }
        
        guard let key = foundKey else {
            throw PGPError.notFound
        }
        
        self.keys.append(key)
    }
    
    /**
     Delete keys
     
     @param keys Keys to delete from the `keys` collection.
     */
    public func delete(keys: [PGPKey]) {
        for key in keys {
            self.keys.removeAll { $0.keyID == key.keyID }
        }
    }
    
    /// Delete all keys;
    public func deleteAll() {
        self.keys.removeAll()
    }
    
    /**
     Export keys data, previously imported, keys of given type (public or secret) to the file at given path.
     
     @param type Keys type.
     @return Data on success.
     */
    public func exportKeys(of type: PGPKeyType) throws -> Data {
        var exportedData = Data()
        for key in keys {
            do {
                let keyData = try key.export(keyType: type)
                exportedData.append(keyData)
            } catch {
                // Skip keys that can't be exported
                continue
            }
        }
        return exportedData
    }
    
    /**
     Export, previously imported, single key data.
     
     @param key Key to export.
     @param armored Choose the format. Binary or Armored (armored is a string based format)
     @return Data, or throws error if can't export the key.
     */
    public func export(key: PGPKey, armored: Bool) throws -> Data {
        let keyData = try key.export()
        
        if armored {
            // TODO: Implement armor conversion
            let armorString = PGPArmor.armored(keyData, as: .publicKey)
            return armorString.data(using: .utf8) ?? keyData
        }
        
        return keyData
    }
    
    /**
     Search imported keys for the key identifier.
     
     @param identifier Key identifier. Short (8 characters, e.g: "4EF122E5") or long (16 characters, e.g: "71180E514EF122E5") identifier.
     @return Key instance, or `nil` if the key is not found.
     */
    public func findKey(_ identifier: String) -> PGPKey? {
        let identifierUpper = identifier.uppercased()
        return keys.first { key in
            let publicID = key.publicKey?.keyID
            let secretID = key.secretKey?.keyID
            
            return publicID?.shortIdentifier.uppercased() == identifierUpper ||
                   publicID?.longIdentifier.uppercased() == identifierUpper ||
                   secretID?.shortIdentifier.uppercased() == identifierUpper ||
                   secretID?.longIdentifier.uppercased() == identifierUpper
        }
    }
    
    /**
     Search imported keys for key id instance.
     
     @param keyID Key identifier.
     @return Key instance or `nil` if not found.
     */
    public func findKey(_ keyID: PGPKeyID) -> PGPKey? {
        return keys.first { key in
            key.publicKey?.keyID?.longIdentifier == keyID.longIdentifier ||
            key.secretKey?.keyID?.longIdentifier == keyID.longIdentifier
        }
    }
    
    /**
     Search imported keys for given user id.
     
     @param userID A string based identifier (usually name with the e-mail address).
     @return Array of found keys, or empty array if not found.
     */
    public func findKeys(_ userID: String) -> [PGPKey] {
        return keys.filter { key in
            let publicUsers = key.publicKey?.users ?? []
            let secretUsers = key.secretKey?.users ?? []
            
            return publicUsers.contains { $0.userID == userID } ||
                   secretUsers.contains { $0.userID == userID }
        }
    }
    
    public func export() throws -> Data {
        return try exportKeys(of: .public)
    }
}

