// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// The consent-sync spike's stand-in for the JitPass panel: it connects to
// the stand-in service, shows a non-activating floating panel the moment a
// request arrives, says "shown" once the panel is on screen, watches for
// the Touch ID dialog to appear and go, and checks it never took focus.
//
//   panel -sock PATH [-auto-deny MS] [-no-ack]
//
// -auto-deny presses Deny by itself MS after the panel shows (the
// unattended cancel test). -no-ack never says "shown" (a stuck app: the
// service must still raise the Touch ID after its wait).

import AppKit
import Foundation

func nowNS() -> Int64 {
    var ts = timespec()
    clock_gettime(CLOCK_REALTIME, &ts)
    return Int64(ts.tv_sec) * 1_000_000_000 + Int64(ts.tv_nsec)
}

var sockPath = ""
var autoDenyMS: Int? = nil
var noAck = false
var args = CommandLine.arguments.dropFirst().makeIterator()
while let a = args.next() {
    switch a {
    case "-sock": sockPath = args.next() ?? ""
    case "-auto-deny": autoDenyMS = Int(args.next() ?? "")
    case "-no-ack": noAck = true
    default: FileHandle.standardError.write("unknown flag \(a)\n".data(using: .utf8)!); exit(2)
    }
}
guard !sockPath.isEmpty else { FileHandle.standardError.write("-sock is required\n".data(using: .utf8)!); exit(2) }

// MARK: - socket

let fd = socket(AF_UNIX, SOCK_STREAM, 0)
var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
withUnsafeMutableBytes(of: &addr.sun_path) { raw in
    sockPath.utf8CString.withUnsafeBytes { src in raw.copyMemory(from: UnsafeRawBufferPointer(rebasing: src.prefix(raw.count))) }
}
var connected = false
for _ in 0..<100 {
    let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
    if rc == 0 { connected = true; break }
    usleep(50_000)
}
guard connected else { FileHandle.standardError.write("could not connect to \(sockPath)\n".data(using: .utf8)!); exit(1) }

let writeLock = NSLock()
func send(_ obj: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return }
    writeLock.lock()
    defer { writeLock.unlock() }
    var bytes = [UInt8](data)
    bytes.append(10)
    _ = bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
}

// MARK: - the Touch ID dialog, seen from outside

/// Polls the on-screen window list every 5 ms for a window that was not
/// there when the request arrived and does not belong to this process.
/// Owner names and window numbers need no Screen Recording permission.
final class DialogWatcher {
    private var baseline = Set<Int>()
    private var seen: Int? = nil
    private let me = Int(getpid())

    private func windows() -> [[String: Any]] {
        (CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]]) ?? []
    }

    func start() {
        baseline = Set(windows().compactMap { $0[kCGWindowNumber as String] as? Int })
        Thread.detachNewThread { [self] in
            let deadline = Date().addingTimeInterval(130)
            while Date() < deadline {
                let list = windows()
                let numbers = Set(list.compactMap { $0[kCGWindowNumber as String] as? Int })
                if let n = seen {
                    if !numbers.contains(n) {
                        send(["t": "dialog_gone", "ns": nowNS()])
                        return
                    }
                } else if let w = list.first(where: {
                    let n = $0[kCGWindowNumber as String] as? Int ?? -1
                    let pid = $0[kCGWindowOwnerPID as String] as? Int ?? -1
                    // The Window Server puts up short-lived windows of its
                    // own around the dialog (the first run latched onto
                    // one on the keychain path); the dialog itself was
                    // coreautha's on every enclave run.
                    let owner = $0[kCGWindowOwnerName as String] as? String ?? ""
                    return pid != me && !baseline.contains(n) && owner != "Window Server"
                }) {
                    seen = w[kCGWindowNumber as String] as? Int
                    let owner = w[kCGWindowOwnerName as String] as? String ?? "?"
                    let layer = w[kCGWindowLayer as String] as? Int ?? 0
                    send(["t": "dialog_seen", "ns": nowNS(), "owner": "\(owner) (layer \(layer))"])
                }
                usleep(5_000)
            }
        }
    }
}

// MARK: - the panel

final class Panel: NSObject {
    let panel: NSPanel
    let status = NSTextField(labelWithString: "Touch ID allows it.")
    let deny = NSButton(title: "Deny", target: nil, action: nil)
    var denied = false

    init(reason: String) {
        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 300, height: 170),
                        styleMask: [.nonactivatingPanel, .titled, .fullSizeContentView],
                        backing: .buffered, defer: false)
        super.init()
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isFloatingPanel = true
        panel.level = .statusBar
        panel.becomesKeyOnlyIfNeeded = true
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.appearance = NSAppearance(named: .darkAqua)
        panel.standardWindowButton(.closeButton)?.isHidden = true
        panel.standardWindowButton(.miniaturizeButton)?.isHidden = true
        panel.standardWindowButton(.zoomButton)?.isHidden = true

        let fx = NSVisualEffectView()
        fx.material = .menu
        fx.state = .active
        panel.contentView = fx

        let head = NSTextField(labelWithString: "Asking")
        head.font = .systemFont(ofSize: 15, weight: .bold)
        let title = NSTextField(wrappingLabelWithString: "jit asks to unlock the vault: every secret it holds, until it locks again")
        title.font = .systemFont(ofSize: 13, weight: .semibold)
        let sub = NSTextField(wrappingLabelWithString: reason)
        sub.font = .systemFont(ofSize: 11)
        sub.textColor = .secondaryLabelColor
        status.font = .systemFont(ofSize: 12)
        deny.target = self
        deny.action = #selector(pressDeny)
        deny.bezelStyle = .rounded
        let foot = NSStackView(views: [status, NSView(), deny])
        foot.orientation = .horizontal
        let stack = NSStackView(views: [head, title, sub, foot])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.edgeInsets = NSEdgeInsets(top: 22, left: 14, bottom: 12, right: 14)
        stack.translatesAutoresizingMaskIntoConstraints = false
        fx.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: fx.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: fx.trailingAnchor),
            stack.topAnchor.constraint(equalTo: fx.topAnchor),
            foot.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -28),
            title.widthAnchor.constraint(equalToConstant: 272),
            sub.widthAnchor.constraint(equalToConstant: 272),
        ])

        if let screen = NSScreen.main {
            let f = screen.visibleFrame
            panel.setFrameTopLeftPoint(NSPoint(x: f.maxX - 310, y: f.maxY - 6))
        }
    }

    /// Shows the panel and returns when it is on screen: ordered front,
    /// drawn, and the drawing flushed to the window server.
    func show() -> Int64 {
        panel.orderFrontRegardless()
        panel.display()
        CATransaction.flush()
        return nowNS()
    }

    @objc func pressDeny() {
        guard !denied else { return }
        denied = true
        status.stringValue = "Denying…"
        send(["t": "deny", "ns": nowNS()])
    }

    func finish(ok: Bool, code: Int) {
        status.stringValue = ok ? "Allowed." : (denied ? "Denied." : "Refused (code \(code)).")
        deny.isEnabled = false
    }
}

// MARK: - main

let app = NSApplication.shared
app.setActivationPolicy(.accessory) // a menu bar app: no Dock icon, never frontmost by itself

var current: Panel? = nil
let watcher = DialogWatcher()

Thread.detachNewThread {
    var buf = [UInt8]()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = read(fd, &chunk, chunk.count)
        if n <= 0 { DispatchQueue.main.async { app.terminate(nil) }; return }
        buf.append(contentsOf: chunk[0..<n])
        while let nl = buf.firstIndex(of: 10) {
            let line = Data(buf[0..<nl])
            buf.removeSubrange(0...nl)
            guard let m = try? JSONSerialization.jsonObject(with: line) as? [String: Any], let t = m["t"] as? String else { continue }
            switch t {
            case "pending":
                watcher.start()
                let before = NSWorkspace.shared.frontmostApplication?.processIdentifier
                DispatchQueue.main.async {
                    let p = Panel(reason: m["reason"] as? String ?? "")
                    current = p
                    let at = p.show()
                    if !noAck { send(["t": "shown", "ns": at]) }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                        let after = NSWorkspace.shared.frontmostApplication?.processIdentifier
                        let stolen = after == getpid() && before != getpid()
                        send(["t": "focus", "stolen": stolen])
                    }
                    if let ms = autoDenyMS {
                        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(ms)) { p.pressDeny() }
                    }
                }
            case "outcome":
                let ok = m["ok"] as? Bool ?? false
                let code = m["code"] as? Int ?? 0
                DispatchQueue.main.async {
                    current?.finish(ok: ok, code: code)
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { app.terminate(nil) }
                }
            default:
                break
            }
        }
    }
}

app.run()
