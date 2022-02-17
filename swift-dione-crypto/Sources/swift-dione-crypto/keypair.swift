//
//  keypair.swift
//  
//
//  Created by Hannes Furmans on 17.02.22.
//

import Foundation
import CryptoKit

public protocol P256Dh {
    @available(macOS 10.15, *)
    func ComputeSharedSecret(pk: CryptoKit.P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

public enum CurveType {
    case P256
    case Curve25519
}

@available(macOS 10.15, *)
public struct P256DhKeypair: P256Dh {
    var type: CurveType
    var privateKey: CryptoKit.P256.KeyAgreement.PrivateKey
    public var publicKey: CryptoKit.P256.KeyAgreement.PublicKey
    
    public init() {
        type = CurveType.P256
        privateKey = CryptoKit.P256.KeyAgreement.PrivateKey()
        publicKey = privateKey.publicKey
    }
    
    public func ComputeSharedSecret(pk: CryptoKit.P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        do {
            return try self.privateKey.sharedSecretFromKeyAgreement(with: pk)
        } catch {
            throw error
        }
    }
}
