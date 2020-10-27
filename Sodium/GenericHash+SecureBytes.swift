//
//  File.swift
//  
//
//  Created by Jakob Offersen on 27/10/2020.
//

import Foundation
import Clibsodium


public extension GenericHash {

    func hash(message: SecureBytes, key: SecureBytes?, outputLength: Int) -> SecureBytes? {
        guard let output = try? SecureBytes(count: outputLength) else { return nil }

        guard .SUCCESS == crypto_generichash(output.pointer , outputLength, message.pointer, UInt64(message.count), key?.pointer, key?.count ?? 0).exitCode else { return nil }

        return output
    }
}
