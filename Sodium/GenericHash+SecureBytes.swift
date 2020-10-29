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

extension GenericHash.Stream {
    /**
     Updates the hash stream with incoming data to contribute to the computed fingerprint.

     - Parameter input: The incoming stream data.

     - Returns: `true` if the data was consumed successfully.
     */
    @discardableResult
    public func update(input: SecureBytes) -> Bool {
        return .SUCCESS == crypto_generichash_update(
            opaqueState,
            input.pointer, UInt64(input.count)
        ).exitCode
    }

    /**
     Signals that the incoming stream of data is complete and triggers computation of the resulting fingerprint.

     - Returns: The computed fingerprint.
     */
    public func final() -> SecureBytes? {
        let outputLen = outputLength
        guard let output = try? SecureBytes(count: outputLen) else { return nil }
        guard .SUCCESS == crypto_generichash_final(
            opaqueState,
            output.pointer, outputLen
        ).exitCode else { return nil }

        return output
    }
}
