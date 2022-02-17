//
//  keypairTest.swift
//  
//
//  Created by Hannes Furmans on 17.02.22.
//

import XCTest
import swift_dione_crypto

class keypairTest: XCTestCase {
    var testPair: P256DhKeypair = P256DhKeypair()
    var securePair: P256SecureDhKeypair = P256SecureDhKeypair()
    var curvePair: Curve25519DhKeypair = Curve25519DhKeypair()
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testP256DhKeypair() throws {
        let pairA = P256DhKeypair()
        let pairB = P256DhKeypair()
        let pubA = pairA.publicKey
        let pubB = pairB.publicKey
        let sharedA = try! pairA.ComputeSharedSecret(pk: pubB)
        let sharedB = try! pairB.ComputeSharedSecret(pk: pubA)
        XCTAssertEqual(sharedA, sharedB, "Shared secrets are not equal")
        self.measure {
            let _ = try! pairA.ComputeSharedSecret(pk: pubB)
        }
    }
    
    func testP256DhKeypairProto() throws {
        let protoPair = testPair.ExportToProto()
        let importedPair = try! P256DhKeypair.init(proto: protoPair)
        XCTAssertEqual(importedPair.publicKey.rawRepresentation, testPair.publicKey.rawRepresentation, "Public keys are not equal")
        
        self.measure {
            let _ = testPair.ExportToProto()
            let _ = try! P256DhKeypair.init(proto: protoPair)
        }
    }
    
    func testP256DhSecureKeypair() throws {
        let pairA = P256SecureDhKeypair()
        let pairB = P256SecureDhKeypair()
        let pubA = pairA.publicKey
        let pubB = pairB.publicKey
        let sharedA = try! pairA.ComputeSharedSecret(pk: pubB)
        let sharedB = try! pairB.ComputeSharedSecret(pk: pubA)
        XCTAssertEqual(sharedA, sharedB, "Shared secrets are not equal")
        self.measure {
            let _ = try! pairA.ComputeSharedSecret(pk: pubB)
        }
    }
    
    func testP256DhSecureKeypairProto() throws {
        let protoPair = securePair.ExportToProto()
        let importedPair = try! P256SecureDhKeypair.init(proto: protoPair)
        XCTAssertEqual(importedPair.publicKey.rawRepresentation, securePair.publicKey.rawRepresentation, "Public keys are not equal")
        
        self.measure {
            let _ = securePair.ExportToProto()
            let _ = try! P256SecureDhKeypair.init(proto: protoPair)
        }
    }
    
    func testCurve25519DhKeypair() throws {
        let pairA = Curve25519DhKeypair()
        let pairB = Curve25519DhKeypair()
        let pubA = pairA.publicKey
        let pubB = pairB.publicKey
        let sharedA = try! pairA.ComputeSharedSecret(pk: pubB)
        let sharedB = try! pairB.ComputeSharedSecret(pk: pubA)
        XCTAssertEqual(sharedA, sharedB, "Shared secrets are not equal")
        self.measure {
            let _ = try! pairA.ComputeSharedSecret(pk: pubB)
        }
    }
    
    func testCurve25519DhKeypairProto() throws {
        let protoPair = curvePair.ExportToProto()
        let importedPair = try! Curve25519DhKeypair.init(proto: protoPair)
        XCTAssertEqual(importedPair.publicKey.rawRepresentation, curvePair.publicKey.rawRepresentation, "Public keys are not equal")
        
        self.measure {
            let _ = curvePair.ExportToProto()
            let _ = try! Curve25519DhKeypair.init(proto: protoPair)
        }
    }
}
