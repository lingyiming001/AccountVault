#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
APP="$PWD/账户保险箱.app"
mkdir -p "$APP/Contents/MacOS"
xcrun swiftc -swift-version 5 -O -target "$(uname -m)-apple-macosx13.0" Sources/Vault.swift Sources/App.swift -o "$APP/Contents/MacOS/AccountVault" -framework SwiftUI -framework AppKit -framework CryptoKit -framework Security
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>AccountVault</string>
<key>CFBundleIdentifier</key><string>local.heart.accountvault</string>
<key>CFBundleName</key><string>账户保险箱</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$APP"
print "已生成：$APP"
