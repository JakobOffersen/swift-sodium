//
//  File.swift
//  
//
//  Created by Jakob Offersen on 27/10/2020.
//

import Foundation
import Clibsodium
import SecureBytes


extension Aead.ChaCha20Poly1305Ietf {
    public func encrypt(message: SecureBytes, secretKey: SecureBytes, additionalData: SecureBytes? = nil, nonce: Nonce? = nil) -> (authenticatedCipherText: Bytes, nonce: Nonce)? {

        guard secretKey.count == KeyBytes else { return nil }

        var authenticatedCipherText = Bytes(count: message.count + ABytes)
        var authenticatedCipherTextLen: UInt64 = 0
        let nonce = nonce ?? self.nonce()

        // safely access pointers to 'authenticatedCipherText', 'message', 'secretKey' and 'additionalData',
        // then make the libsodium-call and bubble its exitcode back up
        let exitCode = message.accessPointer { (messagePointer, messageLength) -> ExitCode in
            secretKey.accessPointer { (secretKeyPointer, _) -> ExitCode in
                if let ad = additionalData { // additional data is present
                    return ad.accessPointer { (adPointer, adLength) -> ExitCode in
                        crypto_aead_chacha20poly1305_ietf_encrypt(
                            &authenticatedCipherText, &authenticatedCipherTextLen,
                            messagePointer, UInt64(messageLength),
                            adPointer, UInt64(adLength),
                            nil, nonce, secretKeyPointer).exitCode
                    }
                } else { // no additional data is present
                    return crypto_aead_chacha20poly1305_ietf_encrypt(
                        &authenticatedCipherText, &authenticatedCipherTextLen,
                        messagePointer, UInt64(message.count),
                        nil, UInt64(0),
                        nil, nonce, secretKeyPointer).exitCode
                }
            }
        }

        guard exitCode == .SUCCESS else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    public func decrypt(authenticatedCipherText: Bytes, secretKey: SecureBytes, nonce: Nonce, additionalData: SecureBytes? = nil) -> SecureBytes? {
        guard authenticatedCipherText.count >= ABytes else { return nil }

        guard let message = try? SecureBytes(count: authenticatedCipherText.count - ABytes) else { return nil }
        var messageLen: UInt64 = 0

        // safely access pointers to 'authenticatedCipherText', 'message', 'secretKey' and 'additionalData',
        // then make the libsodium-call and bubble its exitcode back up
        let exitCode = message.accessPointer { (messagePointer, _) -> ExitCode in
            secretKey.accessPointer { (secretKeyPointer, _) -> ExitCode in
                if let ad = additionalData {
                    return ad.accessPointer { (adPointer, adLength) -> ExitCode in
                        crypto_aead_chacha20poly1305_ietf_decrypt(
                            messagePointer, &messageLen,
                            nil,
                            authenticatedCipherText, UInt64(authenticatedCipherText.count),
                            adPointer, UInt64(adLength),
                            nonce, secretKeyPointer).exitCode
                    }
                } else {
                    return crypto_aead_chacha20poly1305_ietf_decrypt(
                        messagePointer, &messageLen,
                        nil,
                        authenticatedCipherText, UInt64(authenticatedCipherText.count),
                        nil, UInt64(0),
                        nonce, secretKeyPointer).exitCode
                }
            }
        }

        guard exitCode == .SUCCESS else { return nil }

        return message
    }
}
