import Foundation

public protocol SecretKeyGenerator {
    var KeyBytes: Int { get }
    associatedtype Key where Key == Bytes

    static var keygen: (_ k: UnsafeMutablePointer<UInt8>) -> Void { get }
}

extension SecretKeyGenerator {
    /**
     Generates a secret key.

     - Returns: The generated key.
     */
    public func key() -> Key {
        var k = Bytes(count: KeyBytes)
        Self.keygen(&k)
        return k
    }

    public func secureBytesKey() -> SecureBytes? {
        guard let k = try? SecureBytes(count: KeyBytes) else { return nil }
        Self.keygen(k.pointer)
        return k
    }
}
