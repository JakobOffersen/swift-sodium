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
        // Note: No idea if this works....
        guard let k = try? SecureBytes(count: KeyBytes, pointerAccessor: Self.keygen) else { return nil }
        return k
    }
}
