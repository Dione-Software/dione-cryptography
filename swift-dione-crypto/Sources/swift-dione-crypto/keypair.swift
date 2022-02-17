//
//  keypair.swift
//  
//
//  Created by Hannes Furmans on 17.02.22.
//

import Foundation
import CryptoKit
import XCTest

enum ProtoBufKeyPair : Error {
    case invalidCurveType(curveTypeGiven: KeyExchangeProto_PublicKey.Curve)
}

public protocol P256Dh {
    @available(macOS 10.15, *)
    func ComputeSharedSecret(pk: CryptoKit.P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

public protocol ProtoKeypair {
    func ExportToProto() -> KeyExchangeProto_PublicKey
    init(proto: KeyExchangeProto_PublicKey) throws
}

public enum CurveType {
    case P256
    case Curve25519
}

@available(macOS 10.15, *)
func ConvertToSigningKey(pk: P256.KeyAgreement.PublicKey) -> P256.Signing.PublicKey {
    let pk_bytes = pk.rawRepresentation
    return try! P256.Signing.PublicKey.init(rawRepresentation: pk_bytes)
}

@available(macOS 10.15, *)
func ConvertToKeyAgreementKey(pk: P256.Signing.PublicKey) -> P256.KeyAgreement.PublicKey {
    let pk_bytes = pk.rawRepresentation
    return try! P256.KeyAgreement.PublicKey.init(rawRepresentation: pk_bytes)
}

@available(macOS 10.15, *)
public struct P256DhKeypair: P256Dh, ProtoKeypair {
    public init(proto: KeyExchangeProto_PublicKey) throws {
        if proto.curveType != KeyExchangeProto_PublicKey.Curve.p256 {
            throw ProtoBufKeyPair.invalidCurveType(curveTypeGiven: proto.curveType)
        }
        do {
            let sigingPk = try P256.Signing.PublicKey.init(x963Representation: proto.publicKeyData)
            let pk = ConvertToKeyAgreementKey(pk: sigingPk)
            type = CurveType.P256
            privateKey = nil
            publicKey = pk
        } catch {
            throw error
        }
    }
    
    public func ExportToProto() -> KeyExchangeProto_PublicKey {
        var ret = KeyExchangeProto_PublicKey()
        ret.curveType = KeyExchangeProto_PublicKey.Curve.p256
        let sigingPk = ConvertToSigningKey(pk: self.publicKey)
        ret.publicKeyData = sigingPk.x963Representation
        return ret
    }
    
    
    
    var type: CurveType
    var privateKey: CryptoKit.P256.KeyAgreement.PrivateKey?
    public var publicKey: CryptoKit.P256.KeyAgreement.PublicKey
    
    public init() {
        type = CurveType.P256
        privateKey = CryptoKit.P256.KeyAgreement.PrivateKey()
        publicKey = privateKey!.publicKey
    }
    
    public init(pk: CryptoKit.P256.KeyAgreement.PublicKey) {
        type = CurveType.P256
        privateKey = nil
        publicKey = pk
    }
    
    public func ComputeSharedSecret(pk: CryptoKit.P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        do {
            return try self.privateKey!.sharedSecretFromKeyAgreement(with: pk)
        } catch {
            throw error
        }
    }
}

@available(macOS 10.15, *)
public struct P256SecureDhKeypair: P256Dh, ProtoKeypair {
    public func ComputeSharedSecret(pk: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        do {
            return try privateKey!.sharedSecretFromKeyAgreement(with: pk)
        } catch {
            throw error
        }
    }
    
    public func ExportToProto() -> KeyExchangeProto_PublicKey {
        let unsafe_key_pair = P256DhKeypair.init(pk: publicKey)
        return unsafe_key_pair.ExportToProto()
    }
    
    public init(proto: KeyExchangeProto_PublicKey) throws {
        do {
            let unsafe_key_pair = try P256DhKeypair.init(proto: proto)
            publicKey = unsafe_key_pair.publicKey
            privateKey = nil
        } catch {
            throw error
        }
    }
    
    let type = CurveType.P256
    let privateKey: CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey?
    public let publicKey: CryptoKit.P256.KeyAgreement.PublicKey
    
    public init() {
        privateKey = try! CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey()
        publicKey = privateKey!.publicKey
    }
}

@available(macOS 10.15, *)
public struct Curve25519DhKeypair: ProtoKeypair {
    public func ExportToProto() -> KeyExchangeProto_PublicKey {
        var ret = KeyExchangeProto_PublicKey()
        ret.publicKeyData = publicKey.rawRepresentation
        ret.curveType = KeyExchangeProto_PublicKey.Curve.curve25519
        return ret
    }
    
    public init(proto: KeyExchangeProto_PublicKey) throws {
        let protoData = proto.publicKeyData
        var publicKey = Curve25519.KeyAgreement.PrivateKey().publicKey
        do {
            publicKey = try Curve25519.KeyAgreement.PublicKey.init(rawRepresentation: protoData)
        } catch {
            throw error
        }
        self.publicKey = publicKey
        self.privateKey = nil
    }
    
    public func ComputeSharedSecret(pk: Curve25519.KeyAgreement.PublicKey) throws -> SharedSecret {
        do {
            return try privateKey!.sharedSecretFromKeyAgreement(with: pk)
        } catch {
            throw error
        }
    }
    
    let type = CurveType.Curve25519
    let privateKey: CryptoKit.Curve25519.KeyAgreement.PrivateKey?
    public let publicKey: CryptoKit.Curve25519.KeyAgreement.PublicKey
    
    public init() {
        privateKey = Curve25519.KeyAgreement.PrivateKey()
        publicKey = privateKey!.publicKey
    }
    
    public init(pk: Curve25519.KeyAgreement.PublicKey) {
        privateKey = nil
        publicKey = pk
    }
}
