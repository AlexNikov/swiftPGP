// swift-tools-version:5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftPGP",
    platforms: [
        .iOS(.v11),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "SwiftPGP",
            targets: ["SwiftPGP"]),
    ],
    dependencies: [
        // Add dependencies here if needed
    ],
    targets: [
        .target(
            name: "SwiftPGP",
            dependencies: [],
            path: "Sources/SwiftPGP"
        ),
        .testTarget(
            name: "SwiftPGPTests",
            dependencies: ["SwiftPGP"],
            path: "Tests/SwiftPGPTests"
        ),
    ]
)

