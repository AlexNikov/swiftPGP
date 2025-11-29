//
//  PGPPacketFactory.swift
//  SwiftPGP
//

import Foundation

public class PGPPacketFactory {
    
    /// Parse packets from data
    public static func packets(from data: Data) throws -> [PGPPacket] {
        var packets: [PGPPacket] = []
        var offset = 0
        
        while offset < data.count {
            let subdata = data.subdata(in: offset..<data.count)
            
            guard let (bodyData, tag, _, consumedBytes) = PGPPacket.readPacketBody(from: subdata) else {
                // Corrupted or incomplete data
                break
            }
            
            var packet: PGPPacket?
            
            switch tag {
            case .publicKey:
                let keyPacket = PGPPublicKeyPacket()
                try? keyPacket.parse(data: bodyData)
                packet = keyPacket
                
            case .secretKey:
                // Secret key structure is Public Key + Encrypted Secret Part
                let secretPacket = PGPSecretKeyPacket()
                try? secretPacket.parse(data: bodyData)
                packet = secretPacket
                
            case .userID:
                let userPacket = PGPUserIDPacket()
                try? userPacket.parse(data: bodyData)
                packet = userPacket
                
            case .signature:
                let sigPacket = PGPSignaturePacket()
                try? sigPacket.parse(data: bodyData)
                packet = sigPacket
                
            case .literalData:
                let literalPacket = PGPLiteralPacket()
                try? literalPacket.parse(data: bodyData)
                packet = literalPacket
                
            case .publicKeyEncryptedSessionKey:
                let eskPacket = PGPPublicKeyEncryptedSessionKeyPacket()
                try? eskPacket.parse(data: bodyData)
                packet = eskPacket
                
            case .symmetricallyEncryptedIntegrityProtectedData:
                let seipPacket = PGPSymmetricallyEncryptedIntegrityProtectedDataPacket()
                try? seipPacket.parse(data: bodyData)
                packet = seipPacket
                
            case .compressedData:
                let compressedPacket = PGPCompressedPacket()
                try? compressedPacket.parse(data: bodyData)
                packet = compressedPacket
                
            case .onePassSignature:
                let onePassPacket = PGPOnePassSignaturePacket()
                try? onePassPacket.parse(data: bodyData)
                packet = onePassPacket
                
            case .modificationDetectionCode:
                let mdcPacket = PGPModificationDetectionCodePacket()
                try? mdcPacket.parse(data: bodyData)
                packet = mdcPacket
                
            default:
                // Unknown packet, generic container
                // TODO: Implement other packet types
                packet = PGPPacket(tag: tag)
            }
            
            if let p = packet {
                packets.append(p)
            }
            
            offset += consumedBytes
        }
        
        return packets
    }
}

