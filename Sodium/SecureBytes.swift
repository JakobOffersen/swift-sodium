//
//  SecureBytes.swift
//  Note: Why not subclass UnsafeMutableBufferPointer? Because it's a struct, i.e. we cannot hook into the deinit call
//        and thus we cannot leverage the ARC of Swift.
//
//  Created by Jakob Offersen on 14/10/2020.
//

import Foundation
import Clibsodium

public enum SecureBytesError: Error {
    case mlockFailed, outOfBounds, pointerError, custom(String)
}

open class SecureBytes {
    public private(set) var pointer: UnsafeMutablePointer<UInt8>
    private var range: Range<Int>

    public var count: Int {
        range.count
    }

    public var isOnlyZeros: Bool {
        sodium_is_zero(pointer, count) == 1
    }

    public init(count: Int) throws {
        self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        self.pointer.initialize(repeating: 0, count: count)
        self.range = 0..<count

        guard .SUCCESS == sodium_mlock(pointer, count).exitCode else {
            throw SecureBytesError.mlockFailed
        }
    }

    public convenience init(from unsafeRawBufferPointer: UnsafeRawBufferPointer) throws {
        try self.init(count: unsafeRawBufferPointer.count)
        try set(unsafeRawBufferPointer)

        // Clear the original buffer
        let unsafeMutableRawPointer = UnsafeMutableRawPointer(mutating: unsafeRawBufferPointer.baseAddress)
        sodium_memzero(unsafeMutableRawPointer, unsafeRawBufferPointer.count)
        unsafeRawBufferPointer.deallocate()
    }

    public convenience init(from data: Data) throws {
        try self.init(count: data.count)
        try self.set(data)
    }

    public init(secureBytes: SecureBytes) throws {
        // Note: We should NOT mlock or mem-zero the byte range as it is already done for the 'secureBytes' passed to us
        self.pointer = secureBytes.pointer
        self.range = secureBytes.range
    }


    /// Precondition: 'pointer' + 'range' is already properly setup, i.e. pointer is properly initialized and 'range' is a subrange of previous parent-range
    private init(pointer: UnsafeMutablePointer<UInt8>, range: Range<Int>) {
        self.pointer = pointer
        self.range = range
    }

    public convenience init(bytes: [UInt8]) throws {
        try self.init(count: bytes.count)
        try set(bytes)
    }

    deinit {
        free()
    }

    public func free() {
        sodium_memzero(pointer, range.count)
        sodium_munlock(pointer, range.count)
        range = 0..<0
    }

    public func accessBytes(in subrange: Range<Int>) throws -> SecureBytes {
        if !subrange.isSubrange(of: self.range) { throw SecureBytesError.outOfBounds }

        let startIndexPointer = pointer.advanced(by: subrange.startIndex)
        return SecureBytes(pointer: startIndexPointer, range: 0..<subrange.count)
    }

    public func replace(subrange: Range<Int>, with newBytes: SecureBytes) throws {
        guard subrange.isSubrange(of: range) else { throw SecureBytesError.outOfBounds }
        try set(newBytes, offset: subrange.startIndex)
    }

    public func replace(subrange: Range<Int>, with newBytes: Bytes) throws {
        guard subrange.isSubrange(of: range) else { throw SecureBytesError.outOfBounds }
        try set(newBytes, offset: subrange.startIndex)
    }

    public func set(_ input: Bytes, offset: Int = 0) throws {
        var input = input
        if input.count > range.count - offset { throw SecureBytesError.outOfBounds }
        (pointer + offset).initialize(from: &input, count: input.count)
    }

    public func set(_ input: SecureBytes, offset: Int = 0) throws {
        if input.count > range.count - offset { throw SecureBytesError.outOfBounds }
        (pointer + offset).initialize(from: input.pointer, count: input.count)
    }

    public func set(_ input: UnsafeRawBufferPointer, offset: Int = 0) throws {
        if input.count > range.count - offset { throw SecureBytesError.outOfBounds }
        guard let unsafeRawPointer = input.baseAddress?.assumingMemoryBound(to: UInt8.self) else { throw SecureBytesError.pointerError }
        (pointer + offset).initialize(from: unsafeRawPointer, count: input.count)
    }

    public func set(_ input: Data, offset: Int = 0) throws {
        try input.withUnsafeBytes { (unsafeRawBufferPointer) -> Void in
            try self.set(unsafeRawBufferPointer)
        }
    }

//    public func set<T: Collection>(_ input: T, offset: Int = 0) throws where T.Element == UInt8 {
//        if input.count > range.count - offset { throw SecureBytesError.outOfBounds }
//        (pointer + offset).initialize(from: &input as UnsafePointer<UInt8>, count: <#T##Int#>)
//    }

    public func toHex() -> String {
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

/// Note: Only use for debug purposes
extension SecureBytes: CustomStringConvertible {
    public var description: String { toHex() }
}

fileprivate extension Range where Bound == Int {
    func isSubrange(of other: Range<Int>) -> Bool {
        self.startIndex >= other.startIndex && self.endIndex <= other.endIndex
    }
}

extension SecureBytes: Equatable {
    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        lhs.count == rhs.count && sodium_compare(lhs.pointer, rhs.pointer, lhs.count) == 0
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

extension SecureBytes: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: self.pointer, count: self.count)) // Here 'UnsafeRawBufferPointer' init uses the existing memory block. A copy is NOT made according to spec.
    }
}

// Static helpers
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

