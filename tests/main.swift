import Foundation
import CryptoKit

func require(_ value: Bool, _ message: String) { if !value { fatalError(message) } }
let password = "test-master-password-2026"
let salt = try VaultCrypto.random(32)
let key = try VaultCrypto.key(password: password, salt: salt)
let account = Account(title: "测试邮箱", username: "private@example.com", password: "Secret!123", website: "https://example.com", notes: "中文备注")
let encrypted = try VaultCrypto.seal([account], key: key, salt: salt)
let second = try VaultCrypto.seal([account], key: key, salt: salt)
require(encrypted != second, "Each encryption must have a fresh nonce")
require(!String(decoding: encrypted, as: UTF8.self).contains("private@example.com"), "Plaintext leaked")
require(try VaultCrypto.open(encrypted, password: password).0 == [account], "Round trip failed")
do { _ = try VaultCrypto.open(encrypted, password: "wrong"); fatalError("Wrong password accepted") } catch {}
let envelope = try JSONDecoder().decode(Envelope.self, from: encrypted)
var changed = envelope.ciphertext; changed[15] ^= 1
let tampered = try JSONEncoder().encode(Envelope(format: envelope.format, version: 1, iterations: envelope.iterations, salt: salt, ciphertext: changed))
do { _ = try VaultCrypto.open(tampered, password: password); fatalError("Tampering accepted") } catch {}
let invalid = try JSONEncoder().encode(Envelope(format: envelope.format, version: 2, iterations: envelope.iterations, salt: salt, ciphertext: envelope.ciphertext))
do { _ = try VaultCrypto.open(invalid, password: password); fatalError("Unknown version accepted") } catch {}
let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try VaultCrypto.write(encrypted, to: temporary)
let attributes = try FileManager.default.attributesOfItem(atPath: temporary.path)
require((attributes[.posixPermissions] as! NSNumber).intValue == 0o600, "Incorrect permissions")
try FileManager.default.removeItem(at: temporary)
print("PASS: round trip, Unicode, fresh nonce, no plaintext, wrong password, tampering, version, permissions")
