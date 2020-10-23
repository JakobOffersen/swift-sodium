//
//  File.swift
//
//
//  Created by Jakob Offersen on 14/10/2020.
//

import Foundation
import Clibsodium

enum SecureBytesError: Error {
    case mlockFailed
}

class SecureBytes {
    private(set) var pointer: UnsafeMutablePointer<UInt8>
    private(set) var count: Int

    init(count: Int) throws {
        self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        self.pointer.initialize(repeating: 0, count: count)
        self.count = count

        guard .SUCCESS == sodium_mlock(pointer, count).exitCode else {
            throw SecureBytesError.mlockFailed
        }
    }

    deinit {
        free()
    }

    func free() {
        // flush underlying memory of 'bytes'
        sodium_memzero(pointer, count)
        sodium_munlock(pointer, count)
        count = 0
    }
}
