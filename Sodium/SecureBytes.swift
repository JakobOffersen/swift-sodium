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
    case outOfBounds
}

public class SecureBytes {
    public private(set) var pointer: UnsafeMutablePointer<UInt8>
    private var range: Range<Int>

    public var count: Int {
        range.count
    }

    public init(count: Int) throws {
        self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        self.pointer.initialize(repeating: 0, count: count)
        self.range = 0..<count

        guard .SUCCESS == sodium_mlock(pointer, count).exitCode else {
            throw SecureBytesError.mlockFailed
        }
    }

    public convenience init(bytes: [UInt8]) throws {
        try self.init(count: bytes.count)
        try set(bytes)
    }

    /// Precondition: 'pointer' + 'range' is already properly setup, i.e. pointer is properly initialized and 'range' is a subrange of previous parent-range
    private init(pointer: UnsafeMutablePointer<UInt8>, range: Range<Int>) {
        self.pointer = pointer
        self.range = range
    }

    public func accessBytes(in subrange: Range<Int>) throws -> SecureBytes {
        if !subrange.isSubrange(of: self.range) { throw SecureBytesError.outOfBounds }

        let startIndexPointer = pointer.advanced(by: subrange.startIndex)
        return SecureBytes(pointer: startIndexPointer, range: range)
    }

    public func set(_ input: Bytes) throws {
        var input = input //TODO: Allowed?
        if input.count > range.count { throw SecureBytesError.outOfBounds }
        self.pointer.initialize(from: &input, count: input.count)
    }

    public func free() {
        sodium_memzero(pointer, range.count)
        sodium_munlock(pointer, range.count)
        range = 0..<0
    }

    deinit {
        free()
    }
}

/// Note: Only use for debug purposes
extension SecureBytes: CustomStringConvertible {
    public var description: String {
        return (range.reduce("") { (accu, index) -> String in
            let res = accu + String(pointer.pointee)
            pointer += 1
            return res
        })
    }
}

fileprivate extension Range where Bound == Int {
    func isSubrange(of other: Range<Int>) -> Bool {
        self.startIndex >= other.startIndex && self.endIndex <= other.endIndex
    }
}

public extension SecureBytes {
    func toHex() -> String {
        var hexString: String = ""
        let originalPointer = pointer

        for _ in 0 ..< self.count {
            hexString.append(String(format:"%02x", pointer.pointee))
            pointer += 1
        }

        pointer = originalPointer
        return hexString
    }
}

extension SecureBytes: Equatable {
    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        lhs.count == rhs.count && sodium_compare(lhs.pointer, rhs.pointer, lhs.count) == 0
    }
}

extension SecureBytes {
    public static func concat(input: [SecureBytes]) throws -> SecureBytes {
        let combinedSize = input.reduce(0) { (accu, secureBytes) -> Int in
            accu + secureBytes.count
        }

        let combined = try SecureBytes(count: combinedSize)
        var pointerOffset = 0

        input.forEach { (secureBytes) in
            (combined.pointer + pointerOffset).initialize(from: secureBytes.pointer, count: secureBytes.count)
            pointerOffset += secureBytes.count
        }

        return combined
    }
}

extension SecureBytes: Collection {
    public typealias Index = Int
    public typealias Element = UInt8

    public var startIndex: Index { 0 }
    public var endIndex: Index { count }

    public subscript(position: Index) -> Element {
        pointer[position]
    }

    public func index(after i: Index) -> Index {
        i + 1
    }
}
