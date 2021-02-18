// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "Sodium",
    products: [
        .library(
            name: "Sodium",
            targets: ["Sodium"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/JakobOffersen/SecureBytes.git",
            .branch("main")
        ),
    ],
    targets: [
        .target(
            name: "Sodium",
            dependencies: ["SecureBytes"],
            path: "Sodium",
            exclude: ["libsodium", "Info.plist"]),
        .testTarget(
            name: "SodiumTests",
            dependencies: ["Sodium"],
            exclude: ["Info.plist"]),
    ]
)
