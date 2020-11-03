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

        let exitCode = output.accessPointer { (outputPointer, outputLength) -> ExitCode in
            return message.accessPointer { (messagePointer, messageLength) -> ExitCode in
                if let key = key {
                    return key.accessPointer { (keyPointer, keyLength) -> ExitCode in
                        return crypto_generichash(outputPointer, outputLength, messagePointer, UInt64(messageLength), keyPointer, keyLength).exitCode
                    }
                } else {
                    return crypto_generichash(outputPointer, outputLength, messagePointer, UInt64(message.count), nil, 0).exitCode
                }
            }
        }
        guard exitCode == .SUCCESS else { return nil }

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

        let exitCode = input.accessPointer { (inputPointer, inputLength) -> ExitCode in
            return crypto_generichash_update(
                opaqueState,
                inputPointer, UInt64(inputLength)
            ).exitCode
        }

        return exitCode == .SUCCESS
    }

    /**
     Signals that the incoming stream of data is complete and triggers computation of the resulting fingerprint.

     - Returns: The computed fingerprint.
     */
    public func final() -> SecureBytes? {
        let outputLen = outputLength
        guard let output = try? SecureBytes(count: outputLen) else { return nil }

        let exitCode = output.accessPointer { (outputPointer, outputLength) -> ExitCode in
            return crypto_generichash_final(
                opaqueState,
                outputPointer, outputLength
            ).exitCode
        }
        guard exitCode == .SUCCESS else { return nil }

        return output
    }
}
