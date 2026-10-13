import SwiftUI
import AppKit
import CryptoKit
import UniformTypeIdentifiers
typealias VaultState<Value> = SwiftUI.State<Value>

final class VaultStore: ObservableObject {
    @Published var accounts: [Account] = []
    @Published var unlocked = false
    @Published var error = ""
    private var key: SymmetricKey?
    private var salt = Data()
    let url: URL
    init() {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("AccountVault", isDirectory: true)
        url = directory.appendingPathComponent("accounts.avvault")
        do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) } catch { self.error = error.localizedDescription }
    }
    var exists: Bool { FileManager.default.fileExists(atPath: url.path) }
    func unlock(_ password: String) {
        do {
            if exists {
                let result = try VaultCrypto.open(Data(contentsOf: url), password: password)
                accounts = result.0; key = result.1; salt = result.2
            } else {
                guard password.count >= 12 else { error = "请使用至少 12 个字符的主密码。"; return }
                salt = try VaultCrypto.random(32); key = try VaultCrypto.key(password: password, salt: salt)
                try VaultCrypto.write(VaultCrypto.seal([], key: key!, salt: salt), to: url)
            }
            error = ""; unlocked = true
        } catch { self.error = error.localizedDescription; key = nil; accounts = [] }
    }
    func save(_ updated: [Account]) -> Bool {
        guard let key else { return false }
        do { try VaultCrypto.write(VaultCrypto.seal(updated, key: key, salt: salt), to: url); accounts = updated; return true }
        catch { self.error = error.localizedDescription; return false }
    }
    func lock() { accounts = []; key = nil; salt = Data(); unlocked = false; error = "" }
    func exportFile() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "账户备份.avvault"
        guard panel.runModal() == .OK, let destination = panel.url, let key else { return }
        do { try VaultCrypto.write(VaultCrypto.seal(accounts, key: key, salt: salt), to: destination) } catch { self.error = error.localizedDescription }
    }
    func importFile(password: String) -> Bool {
        let panel = NSOpenPanel(); panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let source = panel.url else { return false }
        do {
            let size = try source.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= 20_000_000 else { throw VaultError.invalid }
            let incoming = try VaultCrypto.open(Data(contentsOf: source), password: password).0
            var merged = accounts
            for var item in incoming {
                if merged.contains(where: { $0 == item }) { continue }
                if merged.contains(where: { $0.id == item.id }) { item.id = UUID() }
                merged.append(item)
            }
            return save(merged)
        } catch { self.error = error.localizedDescription; return false }
    }
}

@main struct VaultApp: App {
    @StateObject private var store = VaultStore()
    var body: some Scene {
        WindowGroup("账户保险箱") { ContentView().environmentObject(store).frame(minWidth: 850, minHeight: 570) }
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}
struct ContentView: View {
    @EnvironmentObject var store: VaultStore
    @VaultState<String> private var master = ""
    @VaultState<String> private var confirmation = ""
    @VaultState<String> private var query = ""
    @VaultState<Account?> private var editing: Account?
    @VaultState<Bool> private var importing = false
    @VaultState<String> private var importPassword = ""
    @VaultState<Account?> private var deleting: Account?
    var body: some View {
        Group {
            if store.unlocked {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        Label("账户保险箱", systemImage: "lock.shield.fill").font(.title)
                        Spacer()
                        Button("导入加密文件") { importing = true }
                        Button("导出加密备份") { store.exportFile() }
                        Button("立即锁定") { lock() }
                    }
                    TextField("搜索名称、账号或网址", text: $query)
                    List {
                        ForEach(store.accounts.filter { query.isEmpty || ($0.title + $0.username + $0.website).localizedCaseInsensitiveContains(query) }) { account in
                            HStack {
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(account.title).font(.headline)
                                    Text(account.username).foregroundStyle(.secondary)
                                    if !account.website.isEmpty { Text(account.website).font(.caption).foregroundStyle(.secondary) }
                                }
                                Spacer()
                                Button("查看 / 编辑") { editing = account }
                                Button("删除", role: .destructive) { deleting = account }
                            }.padding(.vertical, 8)
                        }
                    }
                    HStack { Text("共 \(store.accounts.count) 个账户 · 本地加密存储").foregroundStyle(.secondary); Spacer(); Button("添加账户") { editing = Account() }.keyboardShortcut("n") }
                    errorView
                }.padding(24)
            } else {
                VStack(spacing: 18) {
                    Image(systemName: "lock.shield.fill").font(.system(size: 64)).foregroundStyle(.blue)
                    Text(store.exists ? "解锁账户保险箱" : "创建账户保险箱").font(.largeTitle)
                    Text("用主密码登录，所有账户只保存在本机。主密码无法找回。").foregroundStyle(.secondary)
                    SecureField("主密码（至少 12 个字符）", text: $master)
                    if !store.exists { SecureField("再次输入主密码", text: $confirmation) }
                    Button(store.exists ? "登录并解锁" : "创建并解锁") {
                        guard store.exists || master == confirmation else { store.error = "两次主密码不一致。"; return }
                        store.unlock(master); master = ""; confirmation = ""
                    }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    errorView
                }.frame(maxWidth: 440).padding(40)
            }
        }
        .sheet(item: $editing) { account in AccountEditor(account: account) { updated in
            var items = store.accounts
            if let index = items.firstIndex(where: { $0.id == updated.id }) { items[index] = updated } else { items.append(updated) }
            return store.save(items)
        }.environmentObject(store) }
        .sheet(isPresented: $importing) {
            VStack(spacing: 18) {
                Text("导入加密备份").font(.title2)
                Text("输入备份文件的主密码，然后选择 .avvault 文件。账户将合并到当前保险箱。")
                SecureField("备份文件主密码", text: $importPassword)
                errorView
                HStack { Button("取消") { importing = false; importPassword = "" }; Button("选择文件并导入") { if store.importFile(password: importPassword) { importing = false }; importPassword = "" }.disabled(importPassword.isEmpty) }
            }.padding(30).frame(width: 430)
        }
        .alert("删除这个账户？", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) {
            Button("取消", role: .cancel) { deleting = nil }
            Button("删除", role: .destructive) { if let item = deleting { _ = store.save(store.accounts.filter { $0.id != item.id }) }; deleting = nil }
        } message: { Text("删除后可从之前导出的备份恢复。") }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in lock() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in lock() }
    }
    var errorView: some View { Text(store.error).foregroundStyle(.red).font(.callout).textSelection(.enabled) }
    func lock() { editing = nil; importing = false; importPassword = ""; query = ""; store.lock() }
}
struct AccountEditor: View {
    @EnvironmentObject var store: VaultStore
    @Environment(\.dismiss) var dismiss
    @VaultState<Account> var account: Account
    @VaultState<Bool> private var reveal = false
    let save: (Account) -> Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("账户信息").font(.title2)
            TextField("名称，例如：邮箱 / 银行 / 网站", text: $account.title)
            TextField("账号 / 邮箱 / 手机号", text: $account.username)
            HStack {
                if reveal { TextField("密码", text: $account.password) } else { SecureField("密码", text: $account.password) }
                Button(reveal ? "隐藏" : "显示") { reveal.toggle() }
                Button("生成密码") {
                    do { account.password = try VaultCrypto.random(24).base64EncodedString() } catch { store.error = error.localizedDescription }
                }
            }
            TextField("网址", text: $account.website)
            Text("备注").foregroundStyle(.secondary)
            TextEditor(text: $account.notes).frame(height: 100).border(Color.secondary.opacity(0.3))
            Text(store.error).foregroundStyle(.red)
            HStack { Button("取消") { dismiss() }; Spacer(); Button("保存") { if save(account) { dismiss() } }.buttonStyle(.borderedProminent).disabled(account.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) }
        }.padding(28).frame(width: 560)
    }
}
