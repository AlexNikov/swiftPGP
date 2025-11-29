//
//  PGPRSA.swift
//  SwiftPGP
//

import Foundation
import OpenSSL

/// RSA cryptographic operations for PGP
public class PGPRSA {
    
    // MARK: - Encryption & Decryption
    
    /// Public key encryption (for data encryption)
    public static func publicEncrypt(_ data: Data, withPublicKeyPacket publicKeyPacket: PGPPublicKeyPacket) -> Data? {
        guard let rsa = rsaFromPublicKey(publicKeyPacket) else {
            return nil
        }
        defer { RSA_free(rsa) }
        
        // PGP uses PKCS1-v1_5 padding (EMSA-PKCS1-v1_5), but the encryption primitive
        // should be "raw" RSA encryption if we did padding manually, OR we use OpenSSL's PKCS1 padding
        // if the input is raw message.
        // In OpenPGP, for encryption, the data is usually a session key which is already padded/formatted
        // or we need to pad it.
        // RFC 4880 Section 5.1: "The value "m" is derived from the session key... PKCS#1 block encoding EME-PKCS1-v1_5"
        
        // So we should use RSA_PKCS1_PADDING with OpenSSL, which implements EME-PKCS1-v1_5
        
        let rsaSize = Int(RSA_size(rsa))
        var encryptedBytes = [UInt8](repeating: 0, count: rsaSize)
        
        let resultLen = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32 in
            let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress
            return RSA_public_encrypt(Int32(data.count), baseAddress, &encryptedBytes, rsa, RSA_PKCS1_PADDING)
        }
        
        if resultLen < 0 {
            printOpenSSLError()
            return nil
        }
        
        return Data(encryptedBytes.prefix(Int(resultLen)))
    }
    
    /// Private key decryption (for data decryption)
    public static func privateDecrypt(_ data: Data, withSecretKeyPacket secretKeyPacket: PGPSecretKeyPacket) -> Data? {
        guard let rsa = rsaFromSecretKey(secretKeyPacket) else {
            return nil
        }
        defer { RSA_free(rsa) }
        
        let rsaSize = Int(RSA_size(rsa))
        var decryptedBytes = [UInt8](repeating: 0, count: rsaSize)
        
        let resultLen = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32 in
            let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress
            return RSA_private_decrypt(Int32(data.count), baseAddress, &decryptedBytes, rsa, RSA_PKCS1_PADDING)
        }
        
        if resultLen < 0 {
            printOpenSSLError()
            return nil
        }
        
        return Data(decryptedBytes.prefix(Int(resultLen)))
    }
    
    // MARK: - Signing & Verification
    
    /// Private key encryption (for signing)
    public static func privateEncrypt(_ data: Data, withSecretKeyPacket secretKeyPacket: PGPSecretKeyPacket) -> Data? {
        guard let rsa = rsaFromSecretKey(secretKeyPacket) else {
            return nil
        }
        defer { RSA_free(rsa) }
        
        // For signing, PGP calculates the hash, creates the EMSA-PKCS1-v1_5 encoding (which includes padding),
        // and then RSA encrypts that with the private key.
        // However, OpenSSL's RSA_private_encrypt with RSA_PKCS1_PADDING does the padding.
        // But wait, EMSA-PKCS1-v1_5 encoding ALREADY includes padding (00 01 FF ... FF 00 ASN1 HASH).
        // If `data` passed here is already the full EMSA encoded block, we should use RSA_NO_PADDING.
        // In PGPSignaturePacket.verifyRSASignature, we see that we compare decrypted data with EMSA encoded data.
        
        // Let's assume for `privateEncrypt` (signing), the input `data` is the EMSA encoded block (padded hash).
        // So we use RSA_NO_PADDING.
        
        let rsaSize = Int(RSA_size(rsa))
        
        // Input data length must match key size for NO_PADDING
        guard data.count == rsaSize else {
            print("Error: Data length (\(data.count)) does not match RSA key size (\(rsaSize)) for signing")
            return nil
        }
        
        var signatureBytes = [UInt8](repeating: 0, count: rsaSize)
        
        let resultLen = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32 in
            let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress
            return RSA_private_encrypt(Int32(data.count), baseAddress, &signatureBytes, rsa, RSA_NO_PADDING)
        }
        
        if resultLen < 0 {
            printOpenSSLError()
            return nil
        }
        
        return Data(signatureBytes.prefix(Int(resultLen)))
    }
    
    /// Public key decryption (for signature verification)
    public static func publicDecrypt(_ data: Data, withPublicKeyPacket publicKeyPacket: PGPPublicKeyPacket) -> Data? {
        guard let rsa = rsaFromPublicKey(publicKeyPacket) else {
            return nil
        }
        defer { RSA_free(rsa) }
        
        let rsaSize = Int(RSA_size(rsa))
        var decryptedBytes = [UInt8](repeating: 0, count: rsaSize)
        
        let resultLen = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32 in
            let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress
            // Use NO_PADDING to recover the full EMSA block (00 01 ... HASH)
            return RSA_public_decrypt(Int32(data.count), baseAddress, &decryptedBytes, rsa, RSA_NO_PADDING)
        }
        
        if resultLen < 0 {
            printOpenSSLError()
            return nil
        }
        
        return Data(decryptedBytes.prefix(Int(resultLen)))
    }
    
    // MARK: - Key Generation
    
    /// Generate new RSA key pair MPIs
    public static func generateNewKeyMPIArray(bits: Int) -> PGPKeyMaterial? {
        guard let rsa = RSA_new() else { return nil }
        defer { RSA_free(rsa) }
        
        guard let e = BN_new() else { return nil }
        defer { BN_free(e) }
        
        // Set e to 65537 (0x10001)
        BN_set_word(e, 65537)
        
        // Generate key
        if RSA_generate_key_ex(rsa, Int32(bits), e, nil) != 1 {
            printOpenSSLError()
            return nil
        }
        
        // Extract components
        var n: OpaquePointer?
        var e_out: OpaquePointer?
        var d: OpaquePointer?
        RSA_get0_key(rsa, &n, &e_out, &d)
        
        var p: OpaquePointer?
        var q: OpaquePointer?
        RSA_get0_factors(rsa, &p, &q)
        
        // Calculate u = p^(-1) mod q (inverse of p modulo q)
        // OpenPGP requires u < q. OpenSSL might give p and q in different order.
        // RFC 4880: "u = p^-1 mod q" where p is the first prime, q is the second.
        // But usually p > q in PGP conventions or it doesn't strictly matter as long as CRT works.
        // ObjectivePGP calculates u explicitly using BN_mod_inverse.
        
        guard let ctx = BN_CTX_new() else { return nil }
        defer { BN_CTX_free(ctx) }
        
        // We need to duplicate BNs because PGPBigNum takes ownership or copies data
        // For now, we'll convert BN to Data and create PGPMPI
        
        let keyMaterial = PGPKeyMaterial()
        
        if let n = n { keyMaterial.n = mpiFromBN(n, identifier: PGPMPIdentifier.n) }
        if let e = e_out { keyMaterial.e = mpiFromBN(e, identifier: PGPMPIdentifier.e) }
        if let d = d { keyMaterial.d = mpiFromBN(d, identifier: PGPMPIdentifier.d) }
        if let p = p { keyMaterial.p = mpiFromBN(p, identifier: PGPMPIdentifier.p) }
        if let q = q { keyMaterial.q = mpiFromBN(q, identifier: PGPMPIdentifier.q) }
        
        if let p = p, let q = q {
            if let u = BN_mod_inverse(nil, p, q, ctx) {
                keyMaterial.u = mpiFromBN(u, identifier: PGPMPIdentifier.u)
                BN_free(u) // BN_mod_inverse returns a new BIGNUM
            }
        }
        
        return keyMaterial
    }
    
    // MARK: - Helpers
    
    private static func mpiFromBN(_ bn: OpaquePointer, identifier: String) -> PGPMPI? {
        let numBytes = Int(BN_num_bytes(bn))
        var buffer = [UInt8](repeating: 0, count: numBytes)
        BN_bn2bin(bn, &buffer)
        let data = Data(buffer)
        return PGPMPI(bigNum: PGPBigNum(data: data), identifier: identifier)
    }
    
    private static func rsaFromPublicKey(_ packet: PGPPublicKeyPacket) -> OpaquePointer? {
        guard let mpiN = packet.mpi(identifier: PGPMPIdentifier.n),
              let mpiE = packet.mpi(identifier: PGPMPIdentifier.e) else {
            return nil
        }
        
        guard let rsa = RSA_new() else { return nil }
        
        let n = dataToBN(mpiN.bodyData())
        let e = dataToBN(mpiE.bodyData())
        
        RSA_set0_key(rsa, n, e, nil)
        return rsa
    }
    
    private static func rsaFromSecretKey(_ packet: PGPSecretKeyPacket) -> OpaquePointer? {
        // Need public parts (n, e) and private part (d)
        // Optimizations (p, q, u) are optional but good for performance
        guard let mpiN = packet.mpi(identifier: PGPMPIdentifier.n),
              let mpiE = packet.mpi(identifier: PGPMPIdentifier.e),
              let mpiD = packet.secretMPI(identifier: PGPMPIdentifier.d) else {
            return nil
        }
        
        guard let rsa = RSA_new() else { return nil }
        
        let n = dataToBN(mpiN.bodyData())
        let e = dataToBN(mpiE.bodyData())
        let d = dataToBN(mpiD.bodyData())
        
        RSA_set0_key(rsa, n, e, d)
        
        // Optional factors
        if let mpiP = packet.secretMPI(identifier: PGPMPIdentifier.p),
           let mpiQ = packet.secretMPI(identifier: PGPMPIdentifier.q) {
            let p = dataToBN(mpiP.bodyData())
            let q = dataToBN(mpiQ.bodyData())
            RSA_set0_factors(rsa, p, q)
        }
        
        // TODO: Set coefficients (iqmp/u) if available
        
        return rsa
    }
    
    private static func dataToBN(_ data: Data) -> OpaquePointer? {
        return data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> OpaquePointer? in
            let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress
            return BN_bin2bn(baseAddress, Int32(data.count), nil)
        }
    }
    
    private static func printOpenSSLError() {
        let err = ERR_get_error()
        if let errorString = ERR_error_string(err, nil) {
            let message = String(cString: errorString)
            print("OpenSSL Error: \(message)")
        }
    }
}
