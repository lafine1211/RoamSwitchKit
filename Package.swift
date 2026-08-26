// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RoamSwitchKit",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "RoamSwitchKit",
            targets: ["RoamSwitchKit"]
        )
    ],
    targets: [
        .target(
            name: "RoamSwitchKit"
        ),
        .testTarget(
            name: "RoamSwitchKitTests",
            dependencies: ["RoamSwitchKit"]
        )
    ]
)
