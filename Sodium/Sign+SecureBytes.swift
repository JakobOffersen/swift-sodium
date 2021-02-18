//
//  File.swift
//  
//
//  Created by Jakob Offersen on 04/01/2021.
//

import Foundation
import Clibsodium
import SecureBytes

extension Sign {

    private static var PublicKeyBytes: Int { return Int(crypto_sign_publickeybytes()) }
    private static var SecretKeyBytes: Int { return Int(crypto_sign_secretkeybytes()) }

    public struct KeyPairSecureBytes {
        public let publicKey: SecureBytes
        public let secretKey: SecureBytes

        public init(publicKey: PublicKey, secretKey: SecretKey) throws {
            self.publicKey = try SecureBytes(source: publicKey)
            self.secretKey = try SecureBytes(source: secretKey)
        }

        public init(publicKey: SecureBytes, secretKey: SecureBytes) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }

        /// First bytes are 'secretKey', following are 'publicKey'
        public init(data: Data) throws {
            let secretKey = try SecureBytes(count: SecretKeyBytes)
            let publicKey = try SecureBytes(count: PublicKeyBytes)

            secretKey.accessPointer { (pointer, length) -> Void in
                data.copyBytes(to: pointer, from: 0..<length)
            }

            publicKey.accessPointer { (pointer, length) -> Void in
                data.copyBytes(to: pointer, from: SecretKeyBytes..<SecretKeyBytes + length)
            }

            self.init(publicKey: publicKey, secretKey: secretKey)
        }
    }

    public func signature(message: Bytes, secretKey: SecureBytes) -> Bytes? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signature = Array<UInt8>(count: Bytes)

        let exitCode = secretKey.accessPointer { (secretKeyPointer, length) -> ExitCode in
            crypto_sign_detached (
                &signature,
                nil,
                message, UInt64(message.count),
                secretKeyPointer
            ).exitCode
        }

        guard exitCode == .SUCCESS else { return nil }
        return signature
    }

    public func keyPair() throws -> KeyPairSecureBytes {
        let sk = try SecureBytes(count: SecretKeyBytes)
        let pk = try SecureBytes(count: PublicKeyBytes)

        let exitCode = sk.accessPointer { (skPointer, _) -> ExitCode in
            pk.accessPointer { (pkPointer, _) -> ExitCode in
                Self.newKeypair(pkPointer, skPointer).exitCode
            }
        }
        guard exitCode == .SUCCESS else { throw SecureBytesError.pointerError }

        return KeyPairSecureBytes(publicKey: pk, secretKey: sk)
    }
}
