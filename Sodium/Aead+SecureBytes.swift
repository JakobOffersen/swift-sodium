//
//  File.swift
//  
//
//  Created by Jakob Offersen on 27/10/2020.
//

import Foundation
import Clibsodium


extension Aead.ChaCha20Poly1305Ietf {
    public func encrypt(message: Bytes, secretKey: SecureBytes, additionalData: SecureBytes? = nil, nonce: Nonce? = nil) -> (authenticatedCipherText: Bytes, nonce: Nonce)? {

        guard secretKey.count == KeyBytes else { return nil }

        var authenticatedCipherText = Bytes(count: message.count + ABytes)
        var authenticatedCipherTextLen: UInt64 = 0


        let nonce = nonce ?? self.nonce()

        guard .SUCCESS == crypto_aead_chacha20poly1305_ietf_encrypt(
            &authenticatedCipherText, &authenticatedCipherTextLen,
            message, UInt64(message.count),
            additionalData?.pointer, UInt64(additionalData?.count ?? 0),
                nil, nonce, secretKey.pointer).exitCode else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    public func decrypt(authenticatedCipherText: Bytes, secretKey: SecureBytes, nonce: Nonce, additionalData: SecureBytes? = nil) -> SecureBytes? {
        guard authenticatedCipherText.count >= ABytes else { return nil }

        guard let message = try? SecureBytes(count: authenticatedCipherText.count - ABytes) else { return nil }
        var messageLen: UInt64 = 0

        guard .SUCCESS == crypto_aead_chacha20poly1305_ietf_decrypt(
            message.pointer, &messageLen,
            nil,
            authenticatedCipherText, UInt64(authenticatedCipherText.count),
            additionalData?.pointer, UInt64(additionalData?.count ?? 0),
            nonce, secretKey.pointer).exitCode else { return nil }

        return message
    }
}
