import AVFoundation
import Flutter
import MediaPlayer
import Security
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
    let messenger = engineBridge.applicationRegistrar.messenger()
    SecureKeyBridge.register(messenger: messenger)
    // 听书 / 真人讲书：Android 走 ExoPlayer + crypto:// 自定义 DataSource，
    // iOS 之前完全没有实现，补齐后 Dart 侧同一套通道契约即可复用。
    FqPlayerBridge.register(messenger: messenger)
    // 智能朗读：Android 走 TextToSpeech，iOS 用 AVSpeechSynthesizer。
    FqTtsBridge.register(messenger: messenger)
  }
}

/// 本机密钥库（iOS）：Keychain 通用密码项。
///
/// 取代 `flutter_secure_storage`（它在 Windows 端把 `win32` 钉在 5.x，挡住了
/// `wakelock_plus` / `package_info_plus` 的 Built-in Kotlin 版本，见 #205）。
///
/// - 每个条目 = 一个 account，service 固定为 `<bundle id>.secure_keys`；
/// - `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`：后台朗读/播放需要
///   设备首次解锁后即可读取，且绝不随备份恢复到另一台设备；
/// - 查询失败必须区分 `errSecItemNotFound`（真的没有）与其他错误：后者抛给
///   Dart，让 `SecureKeyProvider` 失败关闭，而不是当成“没有密钥”另建一把。
final class SecureKeyBridge {
  private static let service = "\(Bundle.main.bundleIdentifier ?? "fqapp").secure_keys"

  static func register(messenger: FlutterBinaryMessenger) {
    let channel = FlutterMethodChannel(name: "fqapp/secure_keys", binaryMessenger: messenger)
    channel.setMethodCallHandler { call, result in
      guard let arguments = call.arguments as? [String: Any],
        let key = arguments["key"] as? String,
        !key.isEmpty
      else {
        result(FlutterError(code: "BAD_ARGUMENT", message: "缺少 key", details: nil))
        return
      }
      do {
        switch call.method {
        case "read":
          result(try read(key))
        case "write":
          guard let value = arguments["value"] as? String else {
            result(FlutterError(code: "BAD_ARGUMENT", message: "缺少 value", details: nil))
            return
          }
          try write(key, value)
          result(nil)
        case "delete":
          try delete(key)
          result(nil)
        default:
          result(FlutterMethodNotImplemented)
        }
      } catch {
        result(FlutterError(code: "KEYCHAIN", message: error.localizedDescription, details: nil))
      }
    }
  }

  private static func query(_ key: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
    ]
  }

  private static func read(_ key: String) throws -> String? {
    var lookup = query(key)
    lookup[kSecReturnData as String] = true
    lookup[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(lookup as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw KeychainError(status) }
    guard let data = item as? Data else { return nil }
    return String(data: data, encoding: .utf8)
  }

  private static func write(_ key: String, _ value: String) throws {
    let data = Data(value.utf8)
    var update = query(key)
    update[kSecValueData as String] = data
    let updated = SecItemUpdate(query(key) as CFDictionary, update as CFDictionary)
    if updated == errSecSuccess { return }
    if updated != errSecItemNotFound { throw KeychainError(updated) }
    var insert = query(key)
    insert[kSecValueData as String] = data
    insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let added = SecItemAdd(insert as CFDictionary, nil)
    guard added == errSecSuccess else { throw KeychainError(added) }
  }

  private static func delete(_ key: String) throws {
    let status = SecItemDelete(query(key) as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound { return }
    throw KeychainError(status)
  }
}

struct KeychainError: LocalizedError {
  init(_ status: OSStatus) {
    self.status = status
  }

  let status: OSStatus

  var errorDescription: String? {
    SecCopyErrorMessageString(status, nil) as String? ?? "Keychain 错误 \(status)"
  }
}

// MARK: - 听书 / 真人讲书播放桥（iOS）
//
// 数据流与 Android 完全对应，只是把 ExoPlayer 换成 AVPlayer：
//
//   Dart `NativePlayer.create(cdnUrl, keyHex)`
//     → 明文流（keyHex 为空）：AVURLAsset 直接播；
//     → 加密流（keyHex 非空）：native/crypto_core 的 sp_stream_*（CENC AES-CTR）
//       边读边解密，再由 AVAssetResourceLoaderDelegate 把明文字节喂给 AVPlayer。
//
// 为什么实现写在 AppDelegate.swift 里而不是新建文件：新增 Swift 文件必须改
// Runner.xcodeproj/project.pbxproj，而这个工程只能在 CI/Xcode 上验证；同文件
// 追加不碰工程文件，改动面最小。日后要拆分，在 Xcode 里 Add Files to "Runner"
// 再把这些类型搬过去即可。
//
// 未实现（Dart 侧对 iOS 不做要求，或暂不需要）：悬浮窗、系统 TTS 朗读、
// 视频解码器偏好、屏幕亮度/媒体音量直写。

/// 通道名必须与 `lib/services/native_player.dart` 的常量逐字一致。
private let fqPlayerChannel = "fqapp/native_player"
private let fqPlayerEventChannel = "fqapp/native_player/events"

/// 轻量诊断环：只留最近十条，失败时拼进错误文案。
///
/// 为什么要这个：TrollStore 装的包没有 Xcode 控制台，出问题只能靠用户截图。
/// 有了它，错误提示里会直接带「装的是哪一版、卡在哪一步、读了多少字节」，
/// 不用再靠猜。`build` 是版本标记——界面上的提示里没有 `[v3]` 就说明装的还是旧包。
enum FqDiag {
  static let build = "v4"
  private static let lock = NSLock()
  private static var lines: [String] = []
  private static let limit = 70

  static func add(_ line: String) {
    lock.lock()
    lines.append(line)
    if lines.count > limit { lines.removeFirst(lines.count - limit) }
    lock.unlock()
  }

  static var tail: String {
    lock.lock()
    let copy = lines
    lock.unlock()
    return copy.joined(separator: " ")
  }

  static func dump() -> String {
    lock.lock()
    let copy = lines
    lock.unlock()
    return copy.isEmpty ? "(无记录)" : copy.joined(separator: "\n")
  }

  static func fail(_ message: String) -> String {
    let trace = tail
    return trace.isEmpty
      ? "[\(build)] \(message)"
      : "[\(build)] \(message) | \(trace)"
  }
}

// MARK: - 诊断浮层
//
// Dart 侧 `_fail()` 只把无法识别的错误显示成「播放出错，请稍后重试」——
// 原生这边辛苦拼出来的 C 错误原文、AVFoundation domain/code、字节级进度，
// 到界面上一个字都不剩。改 Dart 要动业务代码，风险更大。
//
// 所以在原生层单开一个 UIWindow 把它们铺在屏幕上：既不依赖 Flutter 的文案
// 映射，也不会被路由/弹窗覆盖。定位完问题就把这一段连同调用一起删掉。
final class FqOverlay {
  static let shared = FqOverlay()

  private var window: UIWindow?
  private var textView: UITextView?
  private var payload = ""

  static func show(_ title: String, _ detail: String) {
    shared.present(title, detail)
  }

  private func present(_ title: String, _ detail: String) {
    DispatchQueue.main.async { [weak self] in
      guard let self else { return }
      self.payload = title + "\n\n" + detail
      if let existing = self.textView {
        existing.text = self.payload
        self.window?.isHidden = false
        return
      }
      guard let scene = self.activeScene() else { return }

      let win = UIWindow(windowScene: scene)
      win.windowLevel = .alert + 1
      let root = UIViewController()
      root.view.backgroundColor = UIColor.black.withAlphaComponent(0.95)

      let text = UITextView()
      text.translatesAutoresizingMaskIntoConstraints = false
      text.backgroundColor = .clear
      text.textColor = UIColor(white: 0.96, alpha: 1)
      text.font = UIFont.monospacedSystemFont(ofSize: 12.5, weight: .regular)
      text.isEditable = false
      text.isSelectable = true
      text.text = self.payload
      text.textContainerInset = UIEdgeInsets(top: 14, left: 10, bottom: 14, right: 10)
      root.view.addSubview(text)

      let copy = self.makeButton("复制全文", filled: true)
      copy.addTarget(self, action: #selector(self.copyTapped), for: .touchUpInside)
      let close = self.makeButton("关闭", filled: false)
      close.addTarget(self, action: #selector(self.closeTapped), for: .touchUpInside)
      root.view.addSubview(copy)
      root.view.addSubview(close)

      let guide = root.view.safeAreaLayoutGuide
      NSLayoutConstraint.activate([
        text.topAnchor.constraint(equalTo: guide.topAnchor, constant: 8),
        text.leadingAnchor.constraint(equalTo: root.view.leadingAnchor, constant: 8),
        text.trailingAnchor.constraint(equalTo: root.view.trailingAnchor, constant: -8),
        text.bottomAnchor.constraint(equalTo: copy.topAnchor, constant: -10),

        copy.leadingAnchor.constraint(equalTo: root.view.leadingAnchor, constant: 16),
        copy.trailingAnchor.constraint(equalTo: root.view.trailingAnchor, constant: -16),
        copy.heightAnchor.constraint(equalToConstant: 46),
        copy.bottomAnchor.constraint(equalTo: close.topAnchor, constant: -10),

        close.leadingAnchor.constraint(equalTo: copy.leadingAnchor),
        close.trailingAnchor.constraint(equalTo: copy.trailingAnchor),
        close.heightAnchor.constraint(equalToConstant: 46),
        close.bottomAnchor.constraint(equalTo: guide.bottomAnchor, constant: -12),
      ])

      win.rootViewController = root
      win.isHidden = false
      self.window = win
      self.textView = text
    }
  }

  private func makeButton(_ title: String, filled: Bool) -> UIButton {
    let button = UIButton(type: .system)
    button.translatesAutoresizingMaskIntoConstraints = false
    button.setTitle(title, for: .normal)
    button.titleLabel?.font = .systemFont(ofSize: 16, weight: .semibold)
    button.setTitleColor(.white, for: .normal)
    button.backgroundColor =
      filled ? UIColor(red: 0.85, green: 0.20, blue: 0.22, alpha: 1) : UIColor(white: 0.22, alpha: 1)
    button.layer.cornerRadius = 10
    return button
  }

  private func activeScene() -> UIWindowScene? {
    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    return scenes.first { $0.activationState == .foregroundActive } ?? scenes.first
  }

  @objc private func copyTapped() {
    UIPasteboard.general.string = payload
  }

  @objc private func closeTapped() {
    window?.isHidden = true
    window = nil
    textView = nil
  }
}

final class FqPlayerBridge: NSObject, FlutterStreamHandler {
  static let shared = FqPlayerBridge()

  private let lock = NSLock()
  private var players: [Int: FqAudioPlayer] = [:]
  private var nextPlayerId = 1
  private var eventSink: FlutterEventSink?
  /// Dart 还没开始监听事件通道时先存着。`create` 的回复和 created 事件可能
  /// 抢在 EventChannel 的 listen 之前到达，丢掉 created 会让调用方白等 25 秒。
  private var pendingEmits: [[String: Any]] = []

  static func register(messenger: FlutterBinaryMessenger) {
    let channel = FlutterMethodChannel(name: fqPlayerChannel, binaryMessenger: messenger)
    channel.setMethodCallHandler { call, result in
      FqPlayerBridge.shared.handle(call, result: result)
    }
    let events = FlutterEventChannel(name: fqPlayerEventChannel, binaryMessenger: messenger)
    events.setStreamHandler(FqPlayerBridge.shared)
  }

  // MARK: FlutterStreamHandler

  func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink)
    -> FlutterError?
  {
    lock.lock()
    eventSink = events
    let backlog = pendingEmits
    pendingEmits.removeAll()
    lock.unlock()
    for payload in backlog { events(payload) }
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    lock.lock()
    eventSink = nil
    lock.unlock()
    return nil
  }

  /// Dart 侧 `_handleEvent` 只认 `{"type": ..., "value": ...}` 这一层结构。
  func emit(_ payload: [String: Any]) {
    lock.lock()
    let sink = eventSink
    if sink == nil {
      if pendingEmits.count < 32 { pendingEmits.append(payload) }
      lock.unlock()
      return
    }
    lock.unlock()
    if Thread.isMainThread {
      sink?(payload)
    } else {
      DispatchQueue.main.async { sink?(payload) }
    }
  }

  // MARK: 方法分发

  private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let args = (call.arguments as? [String: Any]) ?? [:]
    switch call.method {
    case "create":
      handleCreate(args, result: result)
    case "play", "pause", "seek", "setVolume", "setMediaVolume", "setRate", "dispose",
      "setKeepScreenOn", "setScreenBrightness", "resetScreenBrightness":
      guard let id = args["id"] as? Int, let player = player(id) else {
        // create 还没回 id 的极早期调用直接忽略：Dart 侧会按超时重试。
        result(nil)
        return
      }
      player.handle(call.method, args)
      result(nil)
    case "getPlaybackSettings":
      guard let id = args["id"] as? Int, let player = player(id) else {
        result(nil)
        return
      }
      result(["volume": player.volume, "rate": player.defaultRate])
    case "canDrawOverlays":
      // 悬浮窗是 Android 专有能力，Dart 侧在非 Android 平台上不会展示入口。
      result(false)
    case "startListenForeground":
      FqNowPlaying.apply(args)
      result(nil)
    case "stopListenForeground":
      FqNowPlaying.clear()
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func handleCreate(_ args: [String: Any], result: @escaping FlutterResult) {
    guard let raw = args["cdnUrl"] as? String, let url = URL(string: raw) else {
      result(FlutterError(code: "BAD_URL", message: "cdnUrl 无效", details: nil))
      return
    }
    let keyHex = (args["keyHex"] as? String) ?? ""
    let startMs = (args["startPositionMs"] as? NSNumber)?.intValue ?? 0

    lock.lock()
    let id = nextPlayerId
    nextPlayerId += 1
    lock.unlock()

    let player = FqAudioPlayer(id: id, url: url, keyHex: keyHex, bridge: self)
    lock.lock()
    players[id] = player
    lock.unlock()

    // 与 Android 一致：先回 playerId（textureId 对纯音频无意义，回 -1）。
    result(["playerId": id, "textureId": -1])
    // created 必须在这里就发，不能等 prepare() 走完：prepare 第一步是
    // sp_stream_open()，那是同步网络读（探长度 + 拉 moov），CDN 慢起来十几秒
    // 起步，而 Dart 侧 create 只给 25 秒。先宣告就绪，真正的失败后面走 error 事件。
    player.announceCreated()
    player.prepare(startMs: startMs)
  }

  private func player(_ id: Int) -> FqAudioPlayer? {
    lock.lock()
    defer { lock.unlock() }
    return players[id]
  }

  func remove(_ id: Int) {
    lock.lock()
    players.removeValue(forKey: id)
    lock.unlock()
  }
}

// MARK: - 单个播放器实例

final class FqAudioPlayer {
  private let id: Int
  private let url: URL
  private let keyHex: String
  private weak var bridge: FqPlayerBridge?

  private var player: AVPlayer?
  private var item: AVPlayerItem?
  private var stream: SpCryptoStream?
  private var loader: SpCryptoLoader?
  private var timeObserver: Any?
  private var statusObservation: NSKeyValueObservation?
  private var controlObservation: NSKeyValueObservation?
  private var endObserver: NSObjectProtocol?
  private var wantPlay = false
  private var disposed = false
  private var lastBuffering: Bool?

  private(set) var volume: Float = 1
  private(set) var defaultRate: Double = 1

  /// 诊断前缀。
  private var tag: String { "p\(id)" }

  init(id: Int, url: URL, keyHex: String, bridge: FqPlayerBridge) {
    self.id = id
    self.url = url
    self.keyHex = keyHex
    self.bridge = bridge
  }

  /// 发事件**必须**带 `playerId`。
  ///
  /// Dart 侧 `NativePlayer._dispatchEvent` 第一件事就是 `event['playerId']`，
  /// 拿不到 num 直接 return——整条事件被静默丢弃。之前漏了这个字段，
  /// created 永远到不了 Dart，`create()` 25 秒后抛超时，UI 就卡在
  /// 「正在加载音频」再变成「加载超时，请检查网络后重试」。
  private func emit(_ type: String, _ value: Any) {
    bridge?.emit(["playerId": id, "type": type, "value": value])
  }

  private func emitError(_ message: String) {
    // 统一带上版本标记和诊断尾巴：界面上一眼能看出是不是新包、卡在哪一步。
    let full = FqDiag.fail(message)
    emit("error", ["message": full])
    // Dart 的 `_fail()` 把不认识的错误一律显示成「播放出错，请稍后重试」，
    // 上面这串详细信息一个字都不会出现在界面上。浮层不经过 Flutter，
    // 所以这里是唯一保证能被看到的地方。
    FqOverlay.show("播放失败诊断", full + "\n\n——— 过程 ———\n" + FqDiag.dump())
  }

  /// Dart 的 `create()` 只有在收到 created 后才认为播放器可用。
  func announceCreated() {
    emit("created", -1)
  }

  // MARK: 准备

  func prepare(startMs: Int) {
    FqDiag.add("\(tag)|P:start")
    // 看门狗：sp_stream_open() 是同步 C 调用，卡在里面无法从外部中断。
    // Dart 那边要等 25 秒才抛超时，用户只能看到「加载超时」这种没信息的话；
    // 这里 12 秒就把真实进度推过去。
    DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in
      guard let self, !self.disposed, self.item == nil else { return }
      self.emitError("准备超时 12s：解密流未就绪")
    }
    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      guard let self else { return }

      // 先判定容器类型，结果无论如何都记进诊断：C 核心后面失败时，
      // 这一行就是「该不该解密」的直接证据。
      let verdict = FqMp4Probe.inspect(url: self.url)
      FqDiag.add("\(self.tag)|probe:\(verdict.described)")
      let plain = verdict.plain
      if plain && !self.keyHex.isEmpty { FqDiag.add("\(self.tag)|bypass:plain") }

      let asset: AVURLAsset
      if self.keyHex.isEmpty || plain {
        // 明文容器：再解密就是破坏数据。直接让 AVPlayer 走原始 https。
        asset = AVURLAsset(
          url: self.url, options: [AVURLAssetPreferPreciseDurationAndTimingKey: true])
      } else {
        guard let stream = SpCryptoStream(url: self.url, keyHex: self.keyHex, tag: self.tag) else {
          self.emitError("加密流打开失败：\(SpCryptoStream.lastOpenError)")
          return
        }
        let loader = SpCryptoLoader(stream: stream)
        // AVPlayer 只对「非 http(s)」的自定义 scheme 走 resourceLoader，
        // 所以把 https 换成 fqapp-crypto，真正的下载仍在 delegate 里按原始 URL 做。
        var components = URLComponents(url: self.url, resolvingAgainstBaseURL: false)
        components?.scheme = SpCryptoLoader.scheme
        // AVFoundation 会用 path 扩展名推断容器类型。CDN 地址常是
        // `/audio?sign=...` 这种没有扩展名的形式，补一个 .mp4 让它少走弯路。
        if let path = components?.path, !path.isEmpty {
          let ext = (path as NSString).pathExtension.lowercased()
          if !["mp4", "m4a", "aac", "mp3"].contains(ext) {
            components?.path = path + ".mp4"
          }
        }
        let wrapped = components?.url ?? self.url
        let wrappedAsset = AVURLAsset(url: wrapped)
        wrappedAsset.resourceLoader.setDelegate(loader, queue: loader.queue)
        self.stream = stream
        self.loader = loader
        asset = wrappedAsset
      }

      DispatchQueue.main.async {
        self.attach(asset: asset, startMs: startMs)
      }
    }
  }

  private func attach(asset: AVURLAsset, startMs: Int) {
    guard !disposed else { return }
    let newItem = AVPlayerItem(asset: asset)
    // 听书常见 1.25x–2x：timeDomain 保证变速不变调，与 Android 的 WSOLA 目标一致。
    newItem.audioTimePitchAlgorithm = .timeDomain
    let newPlayer = AVPlayer(playerItem: newItem)
    // resourceLoader 是同步拉取式供给，AVPlayer 默认会等「足够缓冲」才开播，
    // 等不到就一直 waiting（表现为一直转圈）。关掉后它会立即尝试解码，
    // 数据不够再自行等待，问题也会以具体的 error 暴露出来。
    newPlayer.automaticallyWaitsToMinimizeStalling = false
    newPlayer.volume = volume
    // 只预留 5 秒：自定义数据源是「要多少给多少」，设太大会让播放器
    // 一开始就索要大量数据，反而推迟 readyToPlay。
    newItem.preferredForwardBufferDuration = 5
    item = newItem
    player = newPlayer
    observe(item: newItem, player: newPlayer)
    FqDiag.add("\(tag)|A:\(asset.url.scheme ?? "?")")
    // 第二个看门狗：attachment 建好了、AVPlayer 15 秒还没 ready，说明喂进去的
    // 数据不够，或者它不认这个容器。不报的话用户只会看到一直转圈。
    DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
      guard let self, !self.disposed, let current = self.item,
        current.status != .readyToPlay
      else { return }
      self.emitError("播放器 15s 未就绪")
    }

    // 第三个看门狗，专门抓「状态正常但根本没动」：时长出来了（说明解析成功、
    // status 已是 readyToPlay）、用户也想播，可 8 秒过去播放位置还是 0。
    // 这种情况下前两个看门狗都不会响，界面只会安静地停在 00:00。
    DispatchQueue.main.asyncAfter(deadline: .now() + 6) { [weak self] in
      guard let self, !self.disposed, self.wantPlay,
        let currentItem = self.item, let currentPlayer = self.player,
        CMTimeGetSeconds(currentPlayer.currentTime()) < 0.15
      else { return }
      // 不要求 status 已经是 readyToPlay：数据不对时它会一直停在 unknown，
      // 界面上就是永远的「缓冲中...」，既不报错也不前进——比报错更难查。
      let status: String
      switch currentItem.status {
      case .unknown: status = "unknown"
      case .readyToPlay: status = "ready"
      case .failed: status = "failed"
      @unknown default: status = "?"
      }
      let keepUp = currentItem.isPlaybackLikelyToKeepUp
      let reason = currentPlayer.reasonForWaitingToPlay?.rawValue ?? "none"
      let buffered =
        currentItem.loadedTimeRanges.map { "\(CMTimeGetSeconds($0.timeRangeValue.duration))" }
        .joined(separator: ",")
      self.emitError(
        "6s 无进度 status=\(status) keepUp=\(keepUp) wait=\(reason) buf=\(buffered)")
    }

    if startMs > 0 {
      newPlayer.seek(
        to: CMTime(value: CMTimeValue(startMs), timescale: 1000),
        toleranceBefore: .zero,
        toleranceAfter: .zero)
    }
    // created 已经由 handleCreate 立刻发出（纯音频没有纹理，值恒为 -1），
    // 这里不再重复——重复发虽然无害，但会让「谁负责宣告就绪」变成两处。
    if wantPlay {
      FqAudioPlayer.activateSession()
      newPlayer.play()
    }
  }

  private func observe(item newItem: AVPlayerItem, player newPlayer: AVPlayer) {
    statusObservation = newItem.observe(\.status, options: [.initial, .new]) { [weak self] item, _ in
      guard let self, !self.disposed else { return }
      switch item.status {
      case .readyToPlay:
        let seconds = CMTimeGetSeconds(item.duration)
        FqDiag.add("\(self.tag)|ready:\(Int(seconds))s")
        if seconds.isFinite, seconds > 0 {
          self.emit("duration", Int(seconds * 1000))
        }
        self.emit("firstFrame", true)
      case .failed:
        // 直接把 NSError 的 domain/code 一起带上：AVFoundation 的 -11800 只是
        // 「未知错误」，真正的线索在其 underlying error（例如 -12746 明文校验失败）。
        let error = item.error as NSError?
        let underlying = error?.userInfo[NSUnderlyingErrorKey] as? NSError
        let detail =
          underlying.map { "\($0.domain) \($0.code)" }
          ?? error.map { "\($0.domain) \($0.code)" }
          ?? "unknown"
        self.emitError(
          "\(error?.localizedDescription ?? "播放失败") [\(detail)]")
      default:
        break
      }
    }

    controlObservation = newPlayer.observe(\.timeControlStatus, options: [.new]) {
      [weak self] player, _ in
      guard let self, !self.disposed else { return }
      let playing = player.timeControlStatus == .playing
      self.emit("playing", playing)
      self.emit("playWhenReady", player.rate > 0)
    }

    timeObserver = newPlayer.addPeriodicTimeObserver(
      forInterval: CMTime(seconds: 0.5, preferredTimescale: 600), queue: .main
    ) { [weak self] time in
      guard let self, !self.disposed else { return }
      let ms = Int(CMTimeGetSeconds(time) * 1000)
      if ms >= 0 {
        self.emit("position", ms)
      }
      let buffering = !(self.item?.isPlaybackLikelyToKeepUp ?? true)
      if buffering != self.lastBuffering {
        self.lastBuffering = buffering
        self.emit("buffering", buffering)
      }
    }

    endObserver = NotificationCenter.default.addObserver(
      forName: .AVPlayerItemDidPlayToEndTime, object: newItem, queue: .main
    ) { [weak self] _ in
      guard let self, !self.disposed else { return }
      self.wantPlay = false
      self.emit("completed", true)
      self.emit("playing", false)
    }
  }

  // MARK: 控制

  func handle(_ method: String, _ args: [String: Any]) {
    if disposed { return }
    guard let player else {
      if method == "play" { wantPlay = true }
      if method == "dispose" { dispose() }
      return
    }

    switch method {
    case "play":
      wantPlay = true
      FqAudioPlayer.activateSession()
      player.play()
    case "pause":
      wantPlay = false
      player.pause()
    case "seek":
      let ms = (args["positionMs"] as? NSNumber)?.intValue ?? 0
      player.seek(
        to: CMTime(value: CMTimeValue(max(0, ms)), timescale: 1000),
        toleranceBefore: .zero, toleranceAfter: .zero
      ) { [weak self] _ in
        self?.bridge?.emit(["type": "position", "value": max(0, ms)])
      }
    case "setVolume", "setMediaVolume":
      let value = (args["volume"] as? NSNumber)?.floatValue ?? 1
      volume = value
      player.volume = value
    case "setRate":
      let rate = (args["rate"] as? NSNumber)?.doubleValue ?? 1
      defaultRate = rate
      if player.rate > 0 {
        player.rate = Float(rate)
      }
    case "setKeepScreenOn":
      UIApplication.shared.isIdleTimerDisabled = (args["on"] as? Bool) ?? false
    case "dispose":
      dispose()
    default:
      // 亮度/媒体音量直写是 Android 专有实现，这里保持静默无操作。
      break
    }
  }

  static func activateSession() {
    let session = AVAudioSession.sharedInstance()
    // spokenAudio + playback：锁屏/后台继续放，且走语音优化路由。
    do {
      try session.setCategory(.playback, mode: .spokenAudio)
      try session.setActive(true)
    } catch {
      // 静默失败会表现成「状态在播但没声音」，必须留痕。
      FqDiag.add("sess:\((error as NSError).code)")
    }
  }

  func dispose() {
    guard !disposed else { return }
    disposed = true
    if let timeObserver {
      player?.removeTimeObserver(timeObserver)
    }
    timeObserver = nil
    statusObservation?.invalidate()
    statusObservation = nil
    controlObservation?.invalidate()
    controlObservation = nil
    if let endObserver {
      NotificationCenter.default.removeObserver(endObserver)
    }
    endObserver = nil
    player?.pause()
    player?.replaceCurrentItem(with: nil)
    player = nil
    item = nil
    loader = nil
    stream?.close()
    stream = nil
    bridge?.remove(id)
  }
}

// MARK: - 容器探测
//
// 只拉文件头 64KB 就够判断：CENC 的样本描述一定是 `enca`，并且带 `sinf`
// （内含 `cenc`/`cbcs` scheme）；普通明文 mp4 是 `mp4a` 且没有任何 `sinf`。
//
// 这一步完全走 URLSession，不经过 C 核心，所以即使解密链路打不开，
// 也能回答那个最根本的问题：这份音频到底需不需要解密。
enum FqMp4Probe {
  struct Verdict {
    /// 写进诊断的一行摘要。
    let described: String
    /// 这份文件是否应该**跳过**解密、直接交给 AVPlayer。
    let plain: Bool
  }

  /// CENC 只可能出现在 ISO BMFF（mp4/m4a/m4v）容器里。所以顺序必须是
  /// 「先认容器，再看加密标记」——之前反过来，只找 moov：服务端 TTS 合成的
  /// mp3 压根没有 moov，被判成「未知」，于是照样送进解密核心。拿明文去解密
  /// 得到的是乱码，播放器能嗅出一点点帧头就一直「缓冲中」，永远不出声。
  static func inspect(url: URL) -> Verdict {
    guard !url.isFileURL else { return Verdict(described: "file", plain: false) }
    guard let first = fetch(url, from: 0, to: 65535) else {
      return Verdict(described: "net:fail", plain: false)
    }
    let head = first.data
    let container = sniff(head)
    var marks = ["kind:\(container)"]

    if container != "mp4" {
      // mp3 / ogg / wav / 任何非 BMFF：一定没有 CENC，解密只会毁掉它。
      marks.append("plain")
      return Verdict(described: marks.joined(separator: "+"), plain: true)
    }

    if has(head, "moov") {
      marks.append(contentsOf: cencMarks(head))
      let plain = !has(head, "sinf") && !has(head, "enca")
      marks.append(plain ? "plain" : "cenc")
      return Verdict(described: marks.joined(separator: "+"), plain: plain)
    }

    // moov 在尾部：拉最后 256KB 再判。
    marks.append("moov-tail")
    if first.total > 65536 {
      let from = max(0, first.total - 262_144)
      if let tail = fetch(url, from: from, to: first.total - 1) {
        marks.append(contentsOf: cencMarks(tail.data))
        let plain = !has(tail.data, "sinf") && !has(tail.data, "enca")
        marks.append(plain ? "plain" : "cenc")
        return Verdict(described: marks.joined(separator: "+"), plain: plain)
      }
    }
    marks.append("unknown")
    return Verdict(described: marks.joined(separator: "+"), plain: false)
  }

  /// 按魔数认容器。ISO BMFF 的第一个 box 一定在偏移 4 处。
  private static func sniff(_ data: Data) -> String {
    guard data.count >= 12 else { return "tiny" }
    let magic = [UInt8](data.prefix(4))
    if magic == [0x49, 0x44, 0x33] { return "mp3" }  // "ID3"
    if magic[0] == 0xFF, (magic[1] & 0xE0) == 0xE0 { return "mp3" }  // 帧同步
    if magic == Array("OggS".utf8) { return "ogg" }
    if magic == Array("RIFF".utf8) { return "wav" }
    if magic == Array("fLaC".utf8) { return "flac" }
    let fourcc = String(bytes: data[4..<8], encoding: .isoLatin1) ?? ""
    let boxes = ["ftyp", "styp", "moov", "moof", "mdat", "free", "skip", "wide", "pnot"]
    if boxes.contains(fourcc) { return "mp4" }
    return "other"
  }

  private static func cencMarks(_ data: Data) -> [String] {
    var out: [String] = []
    for tag in ["enca", "sinf", "cenc", "cbcs", "pssh"] where has(data, tag) {
      out.append(tag)
    }
    return out
  }

  private static func has(_ data: Data, _ ascii: String) -> Bool {
    data.range(of: Data(ascii.utf8)) != nil
  }

  private static func fetch(_ url: URL, from: Int64, to: Int64?) -> (data: Data, total: Int64)? {
    var request = URLRequest(url: url)
    let tail = to.map { "\($0)" } ?? ""
    request.setValue("bytes=\(from)-\(tail)", forHTTPHeaderField: "Range")
    request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
    request.timeoutInterval = 8
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = 8
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    let session = URLSession(configuration: configuration)
    defer { session.finishTasksAndInvalidate() }

    let semaphore = DispatchSemaphore(value: 0)
    var payload: Data?
    var response: HTTPURLResponse?
    session.dataTask(with: request) { data, resp, _ in
      payload = data
      response = resp as? HTTPURLResponse
      semaphore.signal()
    }.resume()
    if semaphore.wait(timeout: .now() + 9) == .timedOut { return nil }
    guard let payload, let response else { return nil }

    var total: Int64 = -1
    if let range = response.value(forHTTPHeaderField: "Content-Range"),
      let slash = range.lastIndex(of: "/")
    {
      let value = range[range.index(after: slash)...].trimmingCharacters(in: .whitespaces)
      if value != "*" { total = Int64(value) ?? -1 }
    }
    if total <= 0, let declared = response.value(forHTTPHeaderField: "Content-Length") {
      total = Int64(declared) ?? -1
    }
    return (payload, total)
  }
}

// MARK: - CENC 解密流（native/crypto_core 的 Swift 封装）

/// 与 `native/crypto_core/sp_crypto.h` 的 `sp_stream_*` 一一对应。
///
/// 并发约定（照抄头文件）：流操作由调用方串行化，唯独 cancel 允许随时打断。
/// 所以 read/seek/size/close 走一条串行队列，cancel 直接调 C —— 如果 cancel 也
/// 排队，它会被正在阻塞的 HTTP 读拖住，seek 就无法及时打断旧的请求。
final class SpCryptoStream {
  private var handle: OpaquePointer?
  private var closed = false
  private let pointerLock = NSLock()
  private let queue = DispatchQueue(label: "fq.crypto.stream.ops")
  private let context: SpIOContext

  /// 上一次 open 失败的原因。
  ///
  /// C 侧的 `sp_error.message` 有 192 字节，写得相当具体（哪一步、期望什么、
  /// 实际拿到什么）。之前直接丢掉了，出问题时等于蒙着眼睛——现在原样带进
  /// 错误提示，用户截一张图就能定位。
  private(set) static var lastOpenError = ""

  init?(url: URL, keyHex: String, tag: String) {
    let note: (String) -> Void = { FqDiag.add(tag.isEmpty ? $0 : "\(tag)|\($0)") }
    note("K:\(keyHex.count)")
    guard let key = SpCryptoStream.decodeKey(keyHex) else {
      SpCryptoStream.lastOpenError =
        "密钥格式异常（\(keyHex.count) 个字符，应为 32 位十六进制）"
      note("K:bad")
      return nil
    }
    let ctx = SpIOContext(url: url, tag: tag)
    context = ctx

    let user = Unmanaged.passRetained(ctx).toOpaque()
    let io = UnsafeMutablePointer<sp_io>.allocate(capacity: 1)
    io.initialize(
      to: sp_io(
        user: user, size: fqIoSize, read_at: fqIoReadAt, cancel: fqIoCancel, close: fqIoClose))

    var error = sp_error()
    let opened = key.withUnsafeBufferPointer { buffer -> OpaquePointer? in
      guard let base = buffer.baseAddress else { return nil }
      return sp_stream_open(UnsafePointer(io), base, &error)
    }
    // 打开成功后 I/O 上下文归流所有（头文件约定），io 结构体已被 C 侧按值拷走。
    io.deinitialize(count: 1)
    io.deallocate()

    guard let opened else {
      let code = error.code.rawValue
      let detail = withUnsafePointer(to: &error.message) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: 192) { String(cString: $0) }
      }
      let head = "C 核心返回 \(code)"
      SpCryptoStream.lastOpenError = detail.isEmpty ? head : "\(head)：\(detail)"
      note("O:\(code)")
      Unmanaged<SpIOContext>.fromOpaque(user).release()
      return nil
    }
    note("O:ok")
    handle = opened
  }

  /// keyHex 是 Rust 侧 `derive_spade_content_key` 给出的 32 位十六进制（16 字节）。
  private static func decodeKey(_ hex: String) -> [UInt8]? {
    let trimmed = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count == 32 else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(16)
    var index = trimmed.startIndex
    while index < trimmed.endIndex {
      let next = trimmed.index(index, offsetBy: 2)
      guard let byte = UInt8(trimmed[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    return bytes
  }

  private func liveHandle() -> OpaquePointer? {
    pointerLock.lock()
    defer { pointerLock.unlock() }
    return closed ? nil : handle
  }

  var size: Int64 {
    queue.sync {
      guard let current = liveHandle() else { return -1 }
      return sp_stream_size(current)
    }
  }

  func seek(to position: Int64) -> Int64 {
    queue.sync {
      guard let current = liveHandle() else { return -1 }
      var error = sp_error()
      return sp_stream_seek(current, position, &error)
    }
  }

  func read(into buffer: UnsafeMutablePointer<UInt8>, length: Int) -> Int {
    if length <= 0 { return 0 }
    return queue.sync {
      guard let current = liveHandle() else { return -1 }
      var error = sp_error()
      return sp_stream_read(current, buffer, length, &error)
    }
  }

  /// 「定位 + 读取」必须是一次原子操作。
  ///
  /// AVPlayer 会**并发**发多个区间请求。原来的写法是外层 seek、内层循环 read，
  /// 两者各排一次队：A 的 seek(0) 之后、A 的 read 之前，B 的 seek(800000)
  /// 完全可能插进来，于是 A 读到的是 B 位置的数据。字节整体错位，播放器
  /// 会解析出一个「语法合法但内容是乱的」容器，最后只报一句播放出错。
  ///
  /// 每次读都带上绝对偏移，seek 与 read 在同一队列里连续完成，才不会被插队。
  func readRange(
    offset: Int64, into buffer: UnsafeMutablePointer<UInt8>, length: Int
  ) -> Int {
    if length <= 0 { return 0 }
    return queue.sync {
      guard let current = liveHandle() else { return -1 }
      var error = sp_error()
      guard sp_stream_seek(current, offset, &error) >= 0 else { return -1 }
      return sp_stream_read(current, buffer, length, &error)
    }
  }

  /// 可由任意线程调用，且不排队（见类注释）。
  func cancel() {
    guard let current = liveHandle() else { return }
    sp_stream_cancel(current)
  }

  func close() {
    guard let current = liveHandle() else { return }
    // 先打断可能正在阻塞的那次网络读，再排队关闭：FqAudioPlayer.dispose 在主线程
    // 调用，直接 queue.sync 会被一次 60 秒的 URLSession 拖住，界面就假死了。
    sp_stream_cancel(current)
    queue.async { [self] in
      pointerLock.lock()
      if closed {
        pointerLock.unlock()
        return
      }
      closed = true
      let handle = self.handle
      self.handle = nil
      pointerLock.unlock()
      if let handle {
        // C 侧在 close 里回调 io.close，释放我们 passRetained 的 context。
        sp_stream_close(handle)
      }
    }
  }
}

// MARK: C 回调（C 函数指针不能捕获上下文，统一走 user 指针）

private func fqIoSize(_ user: UnsafeMutableRawPointer?) -> Int64 {
  guard let user else { return -1 }
  return Unmanaged<SpIOContext>.fromOpaque(user).takeUnretainedValue().size()
}

private func fqIoReadAt(
  _ user: UnsafeMutableRawPointer?, _ offset: UInt64, _ buffer: UnsafeMutablePointer<UInt8>?,
  _ length: Int
) -> Int {
  guard let user, let buffer else { return -1 }
  return Unmanaged<SpIOContext>.fromOpaque(user).takeUnretainedValue()
    .read(offset: offset, buffer: buffer, length: length)
}

private func fqIoCancel(_ user: UnsafeMutableRawPointer?) {
  guard let user else { return }
  Unmanaged<SpIOContext>.fromOpaque(user).takeUnretainedValue().cancel()
}

private func fqIoClose(_ user: UnsafeMutableRawPointer?) {
  guard let user else { return }
  let context = Unmanaged<SpIOContext>.fromOpaque(user).takeRetainedValue()
  context.invalidate()
}

/// HTTP / 本地文件的范围读取，对应 Android 的 `HttpBridge` + `OfflineFileBridge`。
/// 契约（与 Kotlin 侧逐条对齐）：size > 0 或 -1；read 返回 >0、0 为 EOF、-1 为错误。
final class SpIOContext {
  private let url: URL
  private let session: URLSession
  private var cachedSize: Int64 = -1
  private var currentTask: URLSessionDataTask?
  /// 服务器忽略 Range（回 200 整份响应）时的落盘缓存：命中后 size / read 全走本地文件，
  /// 否则每次 128KB 读都要重下整个几十 MB 的音频。
  private var fullBodyURL: URL?
  /// 每次 cancel 自增。read 只判断「我这一次请求有没有被打断」，
  /// 不能用布尔标志——那会把流永久废掉：seek 打断一次之后就再也读不出数据。
  private var cancelGeneration = 0
  private var readCount = 0
  private let lock = NSLock()
  /// 诊断前缀（p1 / p2…）。换声音时同时存在多个播放器，日志不加前缀分不清。
  private let tag: String

  init(url: URL, tag: String) {
    self.url = url
    self.tag = tag
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = 30
    configuration.timeoutIntervalForResource = 120
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    session = URLSession(configuration: configuration)
  }

  private func note(_ line: String) {
    FqDiag.add(tag.isEmpty ? line : "\(tag)|\(line)")
  }

  func invalidate() {
    session.invalidateAndCancel()
    lock.lock()
    let cached = fullBodyURL
    fullBodyURL = nil
    lock.unlock()
    if let cached { try? FileManager.default.removeItem(at: cached) }
  }

  func size() -> Int64 {
    if url.isFileURL {
      let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
      let length = (attributes?[.size] as? NSNumber)?.int64Value ?? 0
      return length > 0 ? length : -1
    }
    // 注意：NSLock 不可重入，fetch() 内部要拿同一把锁，所以这里不能跨调用持锁。
    lock.lock()
    let cached = cachedSize
    lock.unlock()
    if cached > 0 { return cached }

    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.setValue("bytes=0-0", forHTTPHeaderField: "Range")
    request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
    // 15 秒：这一步会被 AVPlayer 的 contentInformationRequest 串行等待，
    // 拖太久会让「解析头部」看起来像死机。
    guard let (data, http) = fetch(request, timeout: 10) else {
      note("S:timeout")
      return -1
    }

    // 首选 206：Content-Range 同时证明了「总长度」和「支持随机读」。
    if http.statusCode == 206,
      let total = SpIOContext.totalLength(from: http), total > 0
    {
      lock.lock()
      cachedSize = total
      lock.unlock()
      note("S:\(total)")
      return total
    }

    // 很多 CDN 直接无视 Range 回 200 + 整份响应体。以前这里一律返回 -1，
    // sp_stream_open 拿不到长度就连 moov 都解析不了，UI 只能干等到超时。
    // 现在的降级路径：把这份响应体落盘，之后按本地文件随机读。
    if http.statusCode == 200 {
      if !data.isEmpty, let total = cacheBody(data) {
        note("S200:\(total)")
        return total
      }
      if let declared = http.value(forHTTPHeaderField: "Content-Length")
        .flatMap({ Int64($0) }), declared > 0
      {
        lock.lock()
        cachedSize = declared
        lock.unlock()
        note("S200h:\(declared)")
        return declared
      }
    }
    note("S:\(http.statusCode)")
    return -1
  }

  func read(offset: UInt64, buffer: UnsafeMutablePointer<UInt8>, length: Int) -> Int {
    let result = readInner(offset: offset, buffer: buffer, length: length)
    readCount += 1
    // 只记前几次和所有失败：C 核心一集要读几十上百次，全记会把日志冲干净。
    if readCount <= 4 || result < 0 {
      note("R\(readCount)@\(offset)+\(length)=\(result)")
    }
    return result
  }

  private func readInner(offset: UInt64, buffer: UnsafeMutablePointer<UInt8>, length: Int) -> Int {
    if length <= 0 { return 0 }
    lock.lock()
    let local = fullBodyURL
    let known = cachedSize
    lock.unlock()
    if let local { return readFile(at: local, offset: offset, buffer: buffer, length: length) }
    if url.isFileURL {
      return readFile(at: url, offset: offset, buffer: buffer, length: length)
    }
    // 已知总长且已越过末尾：直接 EOF，别再打一次注定 416 的请求。
    if known > 0, Int64(offset) >= known { return 0 }

    lock.lock()
    let generation = cancelGeneration
    lock.unlock()

    let end = offset &+ UInt64(length) &- 1
    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.setValue("bytes=\(offset)-\(end)", forHTTPHeaderField: "Range")
    request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
    guard let (data, http) = fetch(request, timeout: 12) else { return -1 }
    lock.lock()
    let interrupted = cancelGeneration != generation
    lock.unlock()
    if interrupted { return -1 }

    switch http.statusCode {
    case 206:
      // 空 body 是 EOF，不是错误。C 核心靠 0 判断「读完了」，给 -1 会被当成
      // 故障——一旦当成故障，上层就会以为整段数据到此为止，播放器永远等不完。
      if data.isEmpty { return 0 }
      let count = min(data.count, length)
      copy(data, from: 0, into: buffer, count: count)
      return count
    case 200:
      // 服务器忽略 Range，body 是整份文件：按 offset 切片，并顺手落盘，
      // 让后续 read 直接命中本地缓存。
      let start = Int(offset)
      guard start < data.count else { return 0 }
      let count = min(length, data.count - start)
      copy(data, from: start, into: buffer, count: count)
      _ = cacheBody(data)
      return count
    default:
      return -1
    }
  }

  func cancel() {
    lock.lock()
    cancelGeneration &+= 1
    let task = currentTask
    lock.unlock()
    note("C#\(cancelGeneration)")
    task?.cancel()
  }

  /// 把整份响应体写到临时目录，返回长度；失败返回 nil 并保持原状。
  private func cacheBody(_ data: Data) -> Int64? {
    let target = FileManager.default.temporaryDirectory
      .appendingPathComponent("fq-crypto-\(UUID().uuidString).bin")
    do {
      try data.write(to: target, options: .atomic)
    } catch {
      return nil
    }
    lock.lock()
    let previous = fullBodyURL
    fullBodyURL = target
    cachedSize = Int64(data.count)
    lock.unlock()
    if let previous { try? FileManager.default.removeItem(at: previous) }
    return Int64(data.count)
  }

  private func readFile(
    at fileURL: URL, offset: UInt64, buffer: UnsafeMutablePointer<UInt8>, length: Int
  ) -> Int {
    guard let handle = FileHandle(forReadingAtPath: fileURL.path) else { return -1 }
    defer { try? handle.close() }
    do {
      try handle.seek(toOffset: offset)
      guard let data = try handle.read(upToCount: length) else { return 0 }
      if data.isEmpty { return 0 }
      copy(data, from: 0, into: buffer, count: data.count)
      return data.count
    } catch {
      return -1
    }
  }

  private func copy(
    _ data: Data, from start: Int, into buffer: UnsafeMutablePointer<UInt8>, count: Int
  ) {
    guard count > 0, start >= 0, start + count <= data.count else { return }
    data.withUnsafeBytes { raw in
      if let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) {
        buffer.update(from: base.advanced(by: start), count: count)
      }
    }
  }

  /// C 回调是同步的，这里用信号量把 URLSession 的异步结果拉平。
  private func fetch(_ request: URLRequest, timeout: TimeInterval) -> (Data, HTTPURLResponse)? {
    let semaphore = DispatchSemaphore(value: 0)
    var payload: Data?
    var response: HTTPURLResponse?
    let task = session.dataTask(with: request) { data, resp, _ in
      payload = data
      response = resp as? HTTPURLResponse
      semaphore.signal()
    }
    lock.lock()
    currentTask = task
    lock.unlock()
    task.resume()

    let outcome = semaphore.wait(timeout: .now() + timeout)
    lock.lock()
    currentTask = nil
    lock.unlock()
    if outcome == .timedOut {
      task.cancel()
      return nil
    }
    guard let payload, let response else { return nil }
    return (payload, response)
  }

  private static func totalLength(from response: HTTPURLResponse) -> Int64? {
    guard let value = response.value(forHTTPHeaderField: "Content-Range") else { return nil }
    // 形如 "bytes 0-0/1234567"；总长可能是 "*"，那就当未知。
    guard let slash = value.lastIndex(of: "/") else { return nil }
    let total = value[value.index(after: slash)...].trimmingCharacters(in: .whitespaces)
    if total == "*" { return nil }
    return Int64(total)
  }
}

// MARK: - AVAssetResourceLoader：把解密后的字节交给 AVPlayer

final class SpCryptoLoader: NSObject, AVAssetResourceLoaderDelegate {
  /// 只用于自定义 scheme：AVPlayer 对 http(s) 不会走 resourceLoader。
  static let scheme = "fqapp-crypto"
  let queue = DispatchQueue(label: "fq.crypto.loader")

  private let stream: SpCryptoStream
  private var loggedFirstRequest = false

  init(stream: SpCryptoStream) {
    self.stream = stream
    super.init()
  }

  func resourceLoader(
    _ resourceLoader: AVAssetResourceLoader,
    shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
  ) -> Bool {
    if !loggedFirstRequest {
      loggedFirstRequest = true
      FqDiag.add("LR")
    }
    if let info = loadingRequest.contentInformationRequest {
      // CENC 只加密样本数据，moov/mvhd 仍是明文，所以 MIME 与时长能被正常解析。
      info.contentType = "audio/mp4"
      // 我们的 IO 层对任意 offset 都能读（206 走 Range；200 落盘后按文件切片），
      // 所以无条件声明支持字节范围。长度拿不到就留空，AVPlayer 会自己摸。
      info.isByteRangeAccessSupported = true
      let length = stream.size
      if length > 0 { info.contentLength = length }
      FqDiag.add("CI:\(length)")
    }

    guard let dataRequest = loadingRequest.dataRequest else {
      loadingRequest.finishLoading()
      return true
    }

    let start = dataRequest.requestedOffset
    // AVAssetResourceLoadingDataRequest 有两种「长度」语义：明确的字节数，
    // 或者 requestsAllDataToEndOfResource（此时 requestedLength 是 0/极大值）。
    // 早先一律 start + requestedLength，遇到后者就变成 end == start，
    // 循环一次都不执行，直接 finishLoading()——AVPlayer 收到 0 字节，
    // 却按 contentLength 一直等其余的，最后就报「播放出错」。
    let total = stream.size
    let requested = Int64(dataRequest.requestedLength)
    let wantsTail = dataRequest.requestsAllDataToEndOfResource || requested <= 0
    let end: Int64
    if wantsTail {
      end = total > 0 ? total : start + 1_048_576
    } else {
      end = start &+ requested
    }

    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      guard let self else { return }
      var offset = start
      var chunk = [UInt8](repeating: 0, count: 128 * 1024)
      var retries = 0
      while offset < end, !loadingRequest.isCancelled {
        let want = Int(min(Int64(chunk.count), end - offset))
        if want <= 0 { break }
        let read = chunk.withUnsafeMutableBufferPointer { buffer -> Int in
          guard let base = buffer.baseAddress else { return -1 }
          return self.stream.readRange(offset: offset, into: base, length: want)
        }
        if read < 0 {
          // 一次失败很可能只是这一跳网络抖动。3MB 的文件里任何一次读失败
          // 都会让整个 item 废掉，代价太大，所以同一偏移先重试一次。
          if retries < 1 {
            retries += 1
            continue
          }
        }
        retries = 0
        if read < 0 {
          // 请求已经作废（换声音、拖动进度、切章都会走到这里）：静默退出。
          // 对一个已取消的请求调 finishLoading(with:) 会让 AVPlayer 把这次
          // 失败记在整个 item 上，接着就是 NSOSStatusErrorDomain -1。
          if loadingRequest.isCancelled { return }
          // 真正读失败必须明确告诉 AVPlayer。直接 finishLoading() 等于宣告
          // 「数据就到这里」，而 contentLength 说的是几 MB，它只会一直等剩下
          // 的字节，永远不进入 readyToPlay —— 表现就是「一直转圈然后超时」。
          loadingRequest.finishLoading(
            with: NSError(
              domain: "fqapp.crypto", code: -1,
              userInfo: [NSLocalizedDescriptionKey: FqDiag.fail("解密流读取失败 @\(offset)")]))
          return
        }
        if read == 0 { break }
        dataRequest.respond(with: Data(bytes: chunk, count: read))
        offset += Int64(read)
        if dataRequest.currentOffset >= end { break }
      }
      loadingRequest.finishLoading()
    }
    return true
  }

  func resourceLoader(
    _ resourceLoader: AVAssetResourceLoader, didCancel loadingRequest: AVAssetResourceLoadingRequest
  ) {
    // 这里**不能**调 stream.cancel()。
    //
    // C 侧的 stream 只有一个，cancel 是无差别的：AVPlayer 会同时持有多个
    // 区间请求，取消其中一个（换声音、拖动进度都会）会把另一个正在读的
    // 请求一起打断，那次读返回 -1，我们于是对一个仍然有效的请求报错，
    // 整个 item 直接 failed —— 界面上就是
    // 「The operation could not be completed [NSOSStatusErrorDomain -1]」。
    //
    // 被打断的请求本身已经 isCancelled，下面循环会立刻退出，respond 也会
    // 被播放器忽略，代价只是多读几百 KB。真正需要打断的是销毁播放器，
    // 那条路径走 SpCryptoStream.close()。
  }
}

// MARK: - 锁屏 / 通知中心信息

enum FqNowPlaying {
  static func apply(_ args: [String: Any]) {
    var info = MPNowPlayingInfoCenter.default().nowPlayingInfo ?? [:]
    if let title = args["title"] as? String { info[MPMediaItemPropertyTitle] = title }
    if let episode = args["episode"] as? String { info[MPMediaItemPropertyAlbumTitle] = episode }
    if let position = (args["positionMs"] as? NSNumber)?.doubleValue {
      info[MPNowPlayingInfoPropertyElapsedPlaybackTime] = position / 1000
    }
    if let duration = (args["durationMs"] as? NSNumber)?.doubleValue, duration > 0 {
      info[MPMediaItemPropertyPlaybackDuration] = duration / 1000
    }
    if let speed = (args["speed"] as? NSNumber)?.doubleValue {
      info[MPNowPlayingInfoPropertyPlaybackRate] = speed
    }
    info[MPNowPlayingInfoPropertyIsLiveStream] = false
    MPNowPlayingInfoCenter.default().nowPlayingInfo = info
  }

  static func clear() {
    MPNowPlayingInfoCenter.default().nowPlayingInfo = nil
  }
}

// MARK: - 系统朗读（AVSpeechSynthesizer）
//
// 对应 `lib/services/system_tts.dart` 的 `fqapp/system_tts` +
// `fqapp/system_tts_events`。Android 走 TextToSpeech，iOS 用 AVSpeechSynthesizer，
// 通道契约逐字对齐，Dart 侧一行都不用改。
//
// 事件约定（见 `SystemTtsPlayback._event`）：
//   {type: "start"|"range"|"done"|"error", id}、{type: "interrupted", keepFocus}、
//   {type: "focus_resume"}、{type: "engine_stopped"}。
// `range` 的 start 是相对本段文本的 UTF-16 偏移——和 Dart String 的索引单位
// 一致，正好可以直接加到 _text 的游标上。

final class FqTtsBridge: NSObject, FlutterStreamHandler, AVSpeechSynthesizerDelegate {
  static let shared = FqTtsBridge()

  private let synthesizer = AVSpeechSynthesizer()
  private let lock = NSLock()
  private var eventSink: FlutterEventSink?
  /// utterance → Dart 侧那个 `id`。AVSpeechSynthesizer 只回 utterance 对象本身，
  /// 没有 id 字段，只能自己建映射（对象身份作 key）。
  private var utteranceIds: [ObjectIdentifier: String] = [:]
  private var voice: AVSpeechSynthesisVoice?
  private var rate: Float = 1
  private var volume: Float = 1
  private var observingInterruptions = false

  static func register(messenger: FlutterBinaryMessenger) {
    let channel = FlutterMethodChannel(name: "fqapp/system_tts", binaryMessenger: messenger)
    channel.setMethodCallHandler { call, result in
      FqTtsBridge.shared.handle(call, result: result)
    }
    let events = FlutterEventChannel(
      name: "fqapp/system_tts_events", binaryMessenger: messenger)
    events.setStreamHandler(FqTtsBridge.shared)
    // delegate 必须在任何 speak 之前挂上，否则 start/range/done 一个都收不到，
    // Dart 侧就只能停在「正在切换声音」。
    let bridge = FqTtsBridge.shared
    bridge.synthesizer.delegate = bridge
    bridge.startObservingInterruptions()
  }

  // MARK: FlutterStreamHandler

  func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink)
    -> FlutterError?
  {
    lock.lock()
    eventSink = events
    lock.unlock()
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    lock.lock()
    eventSink = nil
    lock.unlock()
    return nil
  }

  private func emit(_ payload: [String: Any]) {
    lock.lock()
    let sink = eventSink
    lock.unlock()
    guard let sink else { return }
    if Thread.isMainThread {
      sink(payload)
    } else {
      DispatchQueue.main.async { sink(payload) }
    }
  }

  // MARK: 方法分发

  private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let args = (call.arguments as? [String: Any]) ?? [:]
    switch call.method {
    case "engines":
      // 只暴露中文音色：这本书是中文正文，日语/英语音色念出来全是拼音。
      let voices = AVSpeechSynthesisVoice.speechVoices().filter {
        $0.language.hasPrefix("zh")
      }
      // 注意不能写 `x?.identifier as Any`：那会把 Optional 装箱塞进 codec，
      // Flutter 的 StandardMessageCodec 不认识 Optional，编码时直接抛异常。
      let fallbackIdentifier = AVSpeechSynthesisVoice(language: "zh-CN")?.identifier ?? ""
      result([
        "engines": voices.map { ["package": $0.identifier, "label": $0.name] },
        "defaultEngine": fallbackIdentifier,
      ])

    case "initialize":
      if let identifier = args["engine"] as? String, !identifier.isEmpty,
        let picked = AVSpeechSynthesisVoice(identifier: identifier)
      {
        voice = picked
      } else {
        voice = AVSpeechSynthesisVoice(language: "zh-CN")
      }
      if let value = (args["rate"] as? NSNumber)?.floatValue, value > 0 { rate = value }
      if let value = (args["volume"] as? NSNumber)?.floatValue { volume = value }
      // 后台朗读（锁屏继续念）必须有 active 的 playback 会话。
      FqAudioPlayer.activateSession()
      // 返回单段最大字数：中文一句 300 字足够，再长引擎会自己断句。
      result(300)

    case "speak":
      guard let text = args["text"] as? String, !text.isEmpty,
        let id = args["id"] as? String
      else {
        result(FlutterError(code: "BAD_ARGUMENT", message: "缺少 text/id", details: nil))
        return
      }
      let shouldQueue = (args["queue"] as? Bool) ?? false
      result(speak(text: text, id: id, queue: shouldQueue))

    case "setVolume":
      volume = (args["volume"] as? NSNumber)?.floatValue ?? 1
      result(nil)

    case "setRate":
      let value = (args["rate"] as? NSNumber)?.floatValue ?? 1
      if value > 0 { rate = value }
      result(nil)

    case "getPlaybackSettings":
      result(["volume": volume, "rate": rate])

    case "stop", "shutdown":
      synthesizer.stopSpeaking(at: .immediate)
      lock.lock()
      utteranceIds.removeAll()
      lock.unlock()
      result(nil)

    case "pause":
      // 只暂停不丢弃：Dart 侧 resume 会重新走 speak(flush)，届时会先 stop。
      synthesizer.pauseSpeaking(at: .immediate)
      result(nil)

    case "settings":
      if let url = URL(string: UIApplication.openSettingsURLString) {
        UIApplication.shared.open(url)
      }
      result(nil)

    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func speak(text: String, id: String, queue: Bool) -> Any? {
    DispatchQueue.main.async { [weak self] in
      guard let self else { return }
      if !queue {
        // 新的一段朗读：`stopSpeaking` 会同步触发旧 utterance 的 didCancel，
        // 那里只清映射不发事件，所以不会把 done 误报给 Dart。
        self.synthesizer.stopSpeaking(at: .immediate)
      }
      let utterance = AVSpeechUtterance(string: text)
      utterance.voice = self.voice ?? AVSpeechSynthesisVoice(language: "zh-CN")
      // Dart 的 rate 是 0.5–3 的倍速，AVSpeechUtterance.rate 是 0–1 的绝对语速，
      // 默认 0.5 对应「正常」。
      let scaled = AVSpeechUtteranceDefaultSpeechRate * self.rate
      utterance.rate = min(
        max(scaled, AVSpeechUtteranceMinimumSpeechRate), AVSpeechUtteranceMaximumSpeechRate)
      utterance.volume = self.volume
      self.lock.lock()
      self.utteranceIds[ObjectIdentifier(utterance)] = id
      self.lock.unlock()
      self.synthesizer.speak(utterance)
    }
    return nil
  }

  private func identifier(of utterance: AVSpeechUtterance) -> String? {
    lock.lock()
    defer { lock.unlock() }
    return utteranceIds[ObjectIdentifier(utterance)]
  }

  @discardableResult
  private func takeIdentifier(of utterance: AVSpeechUtterance) -> String? {
    lock.lock()
    defer { lock.unlock() }
    return utteranceIds.removeValue(forKey: ObjectIdentifier(utterance))
  }

  // MARK: AVSpeechSynthesizerDelegate

@objc func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didStart utterance: AVSpeechUtterance) {
    guard let id = identifier(of: utterance) else { return }
    emit(["type": "start", "id": id])
  }

@objc func speechSynthesizer(
    _ synthesizer: AVSpeechSynthesizer, willSpeakRangeOfSpeechString characterRange: NSRange,
    utterance: AVSpeechUtterance
  ) {
    guard let id = identifier(of: utterance) else { return }
    emit(["type": "range", "id": id, "start": characterRange.location])
  }

@objc func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didFinish utterance: AVSpeechUtterance) {
    guard let id = takeIdentifier(of: utterance) else { return }
    emit(["type": "done", "id": id])
  }

@objc func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didCancel utterance: AVSpeechUtterance) {
    // 主动打断（换章、暂停、shutdown）不是「念完了」，绝不能报 done，
    // 否则 Dart 侧会把游标推到下一段。
    _ = takeIdentifier(of: utterance)
  }

  // MARK: 音频中断（来电 / 导航 / 其他 App 抢焦点）

  private func startObservingInterruptions() {
    guard !observingInterruptions else { return }
    observingInterruptions = true
    NotificationCenter.default.addObserver(
      self, selector: #selector(handleInterruption(_:)),
      name: AVAudioSession.interruptionNotification, object: nil)
  }

  @objc private func handleInterruption(_ note: Notification) {
    guard let info = note.userInfo,
      let raw = info[AVAudioSessionInterruptionTypeKey] as? UInt,
      let type = AVAudioSession.InterruptionType(rawValue: raw)
    else { return }
    switch type {
    case .began:
      // keepFocus: true —— Dart 侧会按「临时打断」处理，焦点交还时自动续播。
      synthesizer.pauseSpeaking(at: .immediate)
      emit(["type": "interrupted", "keepFocus": true])
    case .ended:
      let options = (info[AVAudioSessionInterruptionOptionKey] as? UInt).map {
        AVAudioSession.InterruptionOptions(rawValue: $0)
      }
      if options?.contains(.shouldResume) ?? false {
        emit(["type": "focus_resume"])
      }
    @unknown default:
      break
    }
  }
}
