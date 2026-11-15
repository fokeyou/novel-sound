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

final class FqPlayerBridge: NSObject, FlutterStreamHandler {
  static let shared = FqPlayerBridge()

  private let lock = NSLock()
  private var players: [Int: FqAudioPlayer] = [:]
  private var nextPlayerId = 1
  private var eventSink: FlutterEventSink?

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
    lock.unlock()
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

    // 与 Android 一致：先回 playerId（textureId 对纯音频无意义，回 -1），
    // 准备完成后再补一个 created 事件。
    result(["playerId": id, "textureId": -1])
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

  init(id: Int, url: URL, keyHex: String, bridge: FqPlayerBridge) {
    self.id = id
    self.url = url
    self.keyHex = keyHex
    self.bridge = bridge
  }

  // MARK: 准备

  func prepare(startMs: Int) {
    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      guard let self else { return }

      let asset: AVURLAsset
      if self.keyHex.isEmpty {
        asset = AVURLAsset(
          url: self.url, options: [AVURLAssetPreferPreciseDurationAndTimingKey: true])
      } else {
        guard let stream = SpCryptoStream(url: self.url, keyHex: self.keyHex) else {
          self.bridge?.emit(["type": "error", "value": ["message": "加密流打开失败"]])
          return
        }
        let loader = SpCryptoLoader(stream: stream)
        // AVPlayer 只对「非 http(s)」的自定义 scheme 走 resourceLoader，
        // 所以把 https 换成 fqapp-crypto，真正的下载仍在 delegate 里按原始 URL 做。
        var components = URLComponents(url: self.url, resolvingAgainstBaseURL: false)
        components?.scheme = SpCryptoLoader.scheme
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
    newPlayer.automaticallyWaitsToMinimizeStalling = true
    newPlayer.volume = volume
    item = newItem
    player = newPlayer
    observe(item: newItem, player: newPlayer)

    if startMs > 0 {
      newPlayer.seek(
        to: CMTime(value: CMTimeValue(startMs), timescale: 1000),
        toleranceBefore: .zero,
        toleranceAfter: .zero)
    }
    bridge?.emit(["type": "created", "value": -1])
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
        if seconds.isFinite, seconds > 0 {
          self.bridge?.emit(["type": "duration", "value": Int(seconds * 1000)])
        }
        self.bridge?.emit(["type": "firstFrame"])
      case .failed:
        let message = item.error?.localizedDescription ?? "播放失败"
        self.bridge?.emit(["type": "error", "value": ["message": message]])
      default:
        break
      }
    }

    controlObservation = newPlayer.observe(\.timeControlStatus, options: [.new]) {
      [weak self] player, _ in
      guard let self, !self.disposed else { return }
      let playing = player.timeControlStatus == .playing
      self.bridge?.emit(["type": "playing", "value": playing])
      self.bridge?.emit(["type": "playWhenReady", "value": player.rate > 0])
    }

    timeObserver = newPlayer.addPeriodicTimeObserver(
      forInterval: CMTime(seconds: 0.5, preferredTimescale: 600), queue: .main
    ) { [weak self] time in
      guard let self, !self.disposed else { return }
      let ms = Int(CMTimeGetSeconds(time) * 1000)
      if ms >= 0 {
        self.bridge?.emit(["type": "position", "value": ms])
      }
      let buffering = !(self.item?.isPlaybackLikelyToKeepUp ?? true)
      if buffering != self.lastBuffering {
        self.lastBuffering = buffering
        self.bridge?.emit(["type": "buffering", "value": buffering])
      }
    }

    endObserver = NotificationCenter.default.addObserver(
      forName: .AVPlayerItemDidPlayToEndTime, object: newItem, queue: .main
    ) { [weak self] _ in
      guard let self, !self.disposed else { return }
      self.wantPlay = false
      self.bridge?.emit(["type": "completed", "value": true])
      self.bridge?.emit(["type": "playing", "value": false])
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
    try? session.setCategory(.playback, mode: .spokenAudio)
    try? session.setActive(true)
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

  init?(url: URL, keyHex: String) {
    guard let key = SpCryptoStream.decodeKey(keyHex) else { return nil }
    let ctx = SpIOContext(url: url)
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
      Unmanaged<SpIOContext>.fromOpaque(user).release()
      return nil
    }
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

  /// 可由任意线程调用，且不排队（见类注释）。
  func cancel() {
    guard let current = liveHandle() else { return }
    sp_stream_cancel(current)
  }

  func close() {
    let current: OpaquePointer? = queue.sync {
      pointerLock.lock()
      defer { pointerLock.unlock() }
      if closed { return nil }
      closed = true
      let handle = self.handle
      self.handle = nil
      return handle
    }
    if let current {
      // C 侧在 close 里回调 io.close，释放我们 passRetained 的 context。
      sp_stream_close(current)
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
  private var cancelled = false
  private let lock = NSLock()

  init(url: URL) {
    self.url = url
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = 30
    configuration.timeoutIntervalForResource = 120
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    session = URLSession(configuration: configuration)
  }

  func invalidate() {
    session.invalidateAndCancel()
  }

  func size() -> Int64 {
    if url.isFileURL {
      let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
      let length = (attributes?[.size] as? NSNumber)?.int64Value ?? 0
      return length > 0 ? length : -1
    }
    // 注意：NSLock 不可重入，perform() 内部要拿同一把锁，所以这里不能跨调用持锁。
    lock.lock()
    let cached = cachedSize
    lock.unlock()
    if cached > 0 { return cached }

    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.setValue("bytes=0-0", forHTTPHeaderField: "Range")
    request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
    let (_, response) = perform(request)
    // 必须拿到 206 且 Content-Range 带总长度：206 之外的响应证明不了支持 Range，
    // 盲目往下读会在 seek 时拿到错位数据。
    guard let http = response, http.statusCode == 206,
      let total = SpIOContext.totalLength(from: http), total > 0
    else {
      return -1
    }
    lock.lock()
    cachedSize = total
    lock.unlock()
    return total
  }

  func read(offset: UInt64, buffer: UnsafeMutablePointer<UInt8>, length: Int) -> Int {
    if length <= 0 { return 0 }
    if url.isFileURL {
      return readFile(offset: offset, buffer: buffer, length: length)
    }
    lock.lock()
    let stopped = cancelled
    lock.unlock()
    if stopped { return -1 }

    let end = offset &+ UInt64(length) &- 1
    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.setValue("bytes=\(offset)-\(end)", forHTTPHeaderField: "Range")
    request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
    let (data, response) = perform(request)
    guard let data, !data.isEmpty, let http = response,
      http.statusCode == 206 || http.statusCode == 200
    else {
      return -1
    }
    let count = min(data.count, length)
    data.withUnsafeBytes { raw in
      if let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) {
        buffer.update(from: base, count: count)
      }
    }
    return count
  }

  func cancel() {
    lock.lock()
    cancelled = true
    let task = currentTask
    lock.unlock()
    task?.cancel()
  }

  private func readFile(offset: UInt64, buffer: UnsafeMutablePointer<UInt8>, length: Int) -> Int {
    guard let handle = FileHandle(forReadingAtPath: url.path) else { return -1 }
    defer { try? handle.close() }
    do {
      try handle.seek(toOffset: offset)
      guard let data = try handle.read(upToCount: length) else { return 0 }
      if data.isEmpty { return 0 }
      data.withUnsafeBytes { raw in
        if let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) {
          buffer.update(from: base, count: data.count)
        }
      }
      return data.count
    } catch {
      return -1
    }
  }

  /// C 回调是同步的，这里用信号量把 URLSession 的异步结果拉平。
  private func perform(_ request: URLRequest) -> (Data?, HTTPURLResponse?) {
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

    if semaphore.wait(timeout: .now() + 60) == .timedOut {
      task.cancel()
      lock.lock()
      currentTask = nil
      lock.unlock()
      return (nil, nil)
    }
    lock.lock()
    currentTask = nil
    lock.unlock()
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

  init(stream: SpCryptoStream) {
    self.stream = stream
    super.init()
  }

  func resourceLoader(
    _ resourceLoader: AVAssetResourceLoader,
    shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
  ) -> Bool {
    if let info = loadingRequest.contentInformationRequest {
      // CENC 只加密样本数据，moov/mvhd 仍是明文，所以 MIME 与时长能被正常解析。
      info.contentType = "audio/mp4"
      let total = stream.size
      if total > 0 {
        info.contentLength = total
        info.isByteRangeAccessSupported = true
      }
    }

    guard let dataRequest = loadingRequest.dataRequest else {
      loadingRequest.finishLoading()
      return true
    }

    let start = dataRequest.requestedOffset
    let end = start + Int64(dataRequest.requestedLength)

    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      guard let self else { return }
      _ = self.stream.seek(to: start)
      var offset = start
      var chunk = [UInt8](repeating: 0, count: 128 * 1024)
      while offset < end, !loadingRequest.isCancelled {
        let want = Int(min(Int64(chunk.count), end - offset))
        if want <= 0 { break }
        let read = chunk.withUnsafeMutableBufferPointer { buffer -> Int in
          guard let base = buffer.baseAddress else { return -1 }
          return self.stream.read(into: base, length: want)
        }
        if read <= 0 { break }
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
    // 打断正在阻塞的那一次范围请求；后续 seek 仍可继续（头文件明确允许）。
    stream.cancel()
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
