import Foundation
import CryptoKit
import CommonCrypto
import Security

struct Account: Codable, Identifiable, Equatable {
    var id = UUID()
    var title = ""
    var username = ""
    var password = ""
    var website = ""
    var notes = ""
}
struct Envelope: Codable {
    let format: String
    let version: Int
    let iterations: Int
    let salt: Data
    let ciphertext: Data
}
enum VaultError: LocalizedError {
    case invalid, random, password
    var errorDescription: String? {
        switch self {
        case .invalid: return "文件格式无效、版本不支持或文件过大。"
        case .random: return "系统随机数生成失败。"
        case .password: return "主密码错误，或文件已损坏 / 被修改。"
        }
    }
}
enum VaultCrypto {
    static let iterations = 600_000
    static func random(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { throw VaultError.random }
        return Data(bytes)
    }
    static func key(password: String, salt: Data) throws -> SymmetricKey {
        let bytes = Array(password.utf8)
        var output = [UInt8](repeating: 0, count: 32)
        let status = bytes.withUnsafeBytes { p in salt.withUnsafeBytes { s in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), p.baseAddress!.assumingMemoryBound(to: Int8.self), bytes.count, s.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations), &output, 32)
        }}
        guard status == kCCSuccess else { throw VaultError.invalid }
        return SymmetricKey(data: output)
    }
    static func seal(_ accounts: [Account], key: SymmetricKey, salt: Data) throws -> Data {
        let box = try AES.GCM.seal(JSONEncoder().encode(accounts), using: key, authenticating: Data("AccountVault:1:600000".utf8))
        return try JSONEncoder().encode(Envelope(format: "AccountVault", version: 1, iterations: iterations, salt: salt, ciphertext: box.combined!))
    }
    static func open(_ data: Data, password: String) throws -> ([Account], SymmetricKey, Data) {
        guard !password.isEmpty, data.count <= 20_000_000 else { throw VaultError.invalid }
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        guard envelope.format == "AccountVault", envelope.version == 1, envelope.iterations == iterations, envelope.salt.count == 32 else { throw VaultError.invalid }
        let key = try key(password: password, salt: envelope.salt)
        do {
            let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.ciphertext), using: key, authenticating: Data("AccountVault:1:600000".utf8))
            return (try JSONDecoder().decode([Account].self, from: plain), key, envelope.salt)
        } catch { throw VaultError.password }
    }
    static func write(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
