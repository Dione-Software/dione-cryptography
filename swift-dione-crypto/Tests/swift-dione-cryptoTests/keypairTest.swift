//
//  keypairTest.swift
//  
//
//  Created by Hannes Furmans on 17.02.22.
//

import XCTest
import swift_dione_crypto

class keypairTest: XCTestCase {

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

}
