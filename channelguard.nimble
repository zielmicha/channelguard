# Package

version       = "0.1.0"
author        = "Michał Zieliński <michal@zielinscy.org.pl>"
description   = "Encrypted tunnel based on Noise_IK handshake"
license       = "MIT"
skipDirs = @["tests"]

# Dependencies

requires "nim >= 0.18.0"
requires "reactor >= 0.4.6"
requires "sodium >= 0.2.0"
