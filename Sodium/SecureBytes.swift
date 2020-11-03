//
//  File.swift
//
//
//  Created by Jakob Offersen on 30/10/2020.
//

import Foundation
import Clibsodium

public enum SecureBytesError: Error {
    case mlockFailed, munlockFailed, outOfBounds, pointerError, custom(String)
}

open class SecureBytes: Collection {

    public typealias Element = UInt8
    public typealias Index = Int

    public var startIndex: Index { 0 }
    public var endIndex: Index { count } // endIndex must be one greater than the last valid index.

    public subscript(position: Int) -> Element { bytes[position] }

    public func index(after i: Int) -> Int { bytes.index(after: i) }

    public private(set) var bytes: ContiguousArray<UInt8>

    public var isOnlyZeros: Bool { bytes.withUnsafeBufferPointer { sodium_is_zero($0.baseAddress, $0.count) == 1 } }

    public var count: Int { bytes.count }

    public init<C>(source: C) throws where Element == C.Element, C: Collection {
        self.bytes = try ContiguousArray(unsafeUninitializedCapacity: source.count, initializingWith: { (buffer, initializedCount) in
            let (_, nextIndex) = buffer.initialize(from: source)
            guard let pointer = buffer.baseAddress else { throw SecureBytesError.pointerError }
            guard .SUCCESS == sodium_mlock(pointer, buffer.count).exitCode else { throw SecureBytesError.mlockFailed }

            // If 'bytes' is empty or too large, 'nextIndex' is set to 'startIndex'
            // or 'endIndex' respectively, else its #bytes written + 1.
            // In the latter case, we should subtract one.
            initializedCount = (nextIndex == buffer.startIndex || nextIndex == buffer.endIndex) ? nextIndex : nextIndex - 1
        })
    }

    public init(count: Int) throws {
        try self.bytes = ContiguousArray.init(unsafeUninitializedCapacity: count, initializingWith: { (buffer, initializedCount) in
            guard let pointer = buffer.baseAddress else { throw SecureBytesError.pointerError }
            sodium_memzero(pointer, count)
            guard .SUCCESS == sodium_mlock(pointer, count).exitCode else { throw SecureBytesError.mlockFailed }
            initializedCount = count
        })
    }

    public init(count: Int, bufferAccessor cb: (UnsafeMutableBufferPointer<UInt8>) -> Void) throws {
        self.bytes = ContiguousArray(unsafeUninitializedCapacity: count, initializingWith: { (buffer, initializedCount) in
            cb(buffer)
            initializedCount = count
        })
    }

    public init(count: Int, pointerAccessor cb: (UnsafeMutablePointer<UInt8>) -> Void) throws {
        self.bytes = try ContiguousArray(unsafeUninitializedCapacity: count, initializingWith: { (buffer, initializedCount) in
            guard let pointer = buffer.baseAddress else { throw SecureBytesError.pointerError }
            cb(pointer)
            initializedCount = count
        })
    }

    public func accessBuffer<R>(cb: (UnsafeMutableBufferPointer<UInt8>) -> R) -> R {
        return bytes.withUnsafeMutableBufferPointer { (buffer) -> R in

            return cb(buffer)
        }
    }

    public func accessPointer<R>(cb: (UnsafeMutablePointer<UInt8>, Int) throws -> R) rethrows -> R {
        return try bytes.withUnsafeMutableBufferPointer { (buffer) -> R in
            guard let pointer = buffer.baseAddress else { throw SecureBytesError.pointerError }
            return try cb(pointer, buffer.count)
        }
    }

    deinit {
        try! free() // force error if free'ing memory is not possible
    }

    public func free() throws {
        try bytes.withUnsafeMutableBytes { buffer in
            guard let pointer = buffer.baseAddress else { throw SecureBytesError.pointerError }
            sodium_memzero(pointer, buffer.count)
            guard .SUCCESS == sodium_munlock(pointer, buffer.count).exitCode else { throw SecureBytesError.munlockFailed }
        }
    }

    public func viewBytes(in subrange: Range<Int>) -> ArraySlice<UInt8> {
        precondition(subrange.isSubrange(of: bytes.range), "tried to access too large subrange")
        return bytes[subrange]
    }

    public func replace<C>(subrange: Range<Int>, with newElements: C) where C.Element == Element, C: Collection {
        precondition(subrange.isSubrange(of: bytes.range), "tried to replace too large subrange")
        self.bytes.replaceSubrange(subrange, with: newElements)
    }

    public func write<C>(source: C, offset: Int = 0) where Element == C.Element, Index == C.Index, C: Collection {
        let writeRange = (source.startIndex ..< source.endIndex).offset(by: offset)
        precondition(writeRange.isSubrange(of: bytes.range), "tried to write too large subrange")
        self.bytes.replaceSubrange(writeRange, with: source)
    }

    public func toHex() -> String {
        return bytes.reduce("") {$0 + String(format:"%02x", $1)}
    }
}

extension SecureBytes: Equatable {
    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        lhs.bytes == rhs.bytes
    }
}

fileprivate extension Range where Bound == Int {
    func offset(by offset: Int) -> Range<Int> {
        (offset + startIndex)..<(offset + endIndex)
    }

    func isSubrange(of other: Range<Int>) -> Bool {
        self.startIndex >= other.startIndex && self.endIndex <= other.endIndex
    }
}

fileprivate extension Collection where Index == Int  {
    var range: Range<Int> { startIndex..<endIndex }
}

// static helpers
extension SecureBytes {
    public static func concat(input: [SecureBytes]) throws -> SecureBytes {
        let combinedSize = input.reduce(0) { (accu, secureBytes) -> Int in
            accu + secureBytes.count
        }

        let combined = try SecureBytes(count: combinedSize)
        var offset = 0
        input.forEach { (secureBytes) in
            combined.write(source: secureBytes, offset: offset)
            offset += secureBytes.count
        }

        return combined
    }
}
