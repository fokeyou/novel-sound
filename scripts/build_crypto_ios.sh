#!/usr/bin/env bash
# 把 native/crypto_core 编成 iOS arm64 静态库，供 AVPlayer 那条路径做 CENC 解密。
#
# 与 Android 的差异：Android 用 native/android/jni_bridge.c 把 sp_io 的 HTTP
# 回调转给 Kotlin（OkHttp）；iOS 不需要 JNI，Swift 直接实现 sp_io 回调
# （见 ios/Runner/AppDelegate.swift 里的 SpIOContext），所以这里只编核心库。
#
# 必须在 `flutter build ios` 之前执行，否则 Release/Debug.xcconfig 里的
# -force_load 找不到 libspcrypto.a 会链接失败。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$ROOT/native/crypto_core"
OUT_DIR="$ROOT/ios/Frameworks"
OUT="$OUT_DIR/libspcrypto.a"
MIN_IOS="${MIN_IOS:-15.0}"
ARCH="${ARCH:-arm64}"

if ! command -v xcrun >/dev/null 2>&1; then
  echo "错误：未找到 xcrun，请在 macOS + Xcode 环境执行" >&2
  exit 1
fi

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 与 native/CMakeLists.txt 的 sp_crypto_core 目标保持一致：
# 源码集合、include 路径、tiny-AES-c 的 AES-128-ECB-only 编译宏都不能偏。
SOURCES=(
  "$CORE/sp_error.c"
  "$CORE/sp_stream.c"
  "$CORE/mp4_cenc.c"
  "$CORE/sp_aes.c"
  "$ROOT/native/third_party/tiny_aes/aes.c"
)

echo "==> sysroot: $SDK"
echo "==> arch: $ARCH  min iOS: $MIN_IOS"

# ---------- 自动配置 Xcode 工程（全部幂等，重复执行不叠加） ----------
# 这一步是刻意的设计：bridging header / xcconfig / Info.plist 三处改动都很小，
# 但都要手动改文件。放到脚本里做，补丁文件就从 7 个降到 3 个。
echo "==> 自动配置工程（bridging header / xcconfig / Info.plist）"

BH="$ROOT/ios/Runner/Runner-Bridging-Header.h"
if [ ! -f "$BH" ]; then
  printf '#import "GeneratedPluginRegistrant.h"\n' > "$BH"
fi
if grep -q 'crypto_core/sp_crypto.h' "$BH"; then
  echo "    bridging header: 已包含 sp_crypto.h，跳过"
else
  cat >> "$BH" <<'HEADER_EOF'

// CENC 解密核心（native/crypto_core），由 scripts/build_crypto_ios.sh 编译并链接。
#include "../../native/crypto_core/sp_crypto.h"
HEADER_EOF
  echo "    bridging header: 已追加 sp_crypto.h"
fi

for cfg in "$ROOT/ios/Flutter/Release.xcconfig" "$ROOT/ios/Flutter/Debug.xcconfig"; do
  [ -f "$cfg" ] || continue
  if grep -q 'libspcrypto.a' "$cfg"; then
    echo "    $(basename "$cfg"): 已配置，跳过"
  else
    cat >> "$cfg" <<'XC_EOF'

// ---- iOS 真人讲书：链接 CENC 解密核心（scripts/build_crypto_ios.sh 产出）----
HEADER_SEARCH_PATHS = $(inherited) "$(SRCROOT)/../native/crypto_core"
OTHER_LDFLAGS = $(inherited) -force_load "$(SRCROOT)/Frameworks/libspcrypto.a"
XC_EOF
    echo "    $(basename "$cfg"): 已追加 HEADER_SEARCH_PATHS + OTHER_LDFLAGS"
  fi
done

PLIST="$ROOT/ios/Runner/Info.plist"
PB="${PLISTBUDDY:-/usr/libexec/PlistBuddy}"
if [ ! -f "$PLIST" ]; then
  echo "    警告：未找到 Info.plist，后台播放可能失效" >&2
elif [ ! -x "$PB" ]; then
  echo "    警告：未找到 $PB，请手动给 Info.plist 加 UIBackgroundModes=[audio]" >&2
elif "$PB" -c "Print :UIBackgroundModes" "$PLIST" >/dev/null 2>&1; then
  if "$PB" -c "Print :UIBackgroundModes" "$PLIST" 2>/dev/null | grep -q 'audio'; then
    echo "    Info.plist: UIBackgroundModes 已含 audio，跳过"
  else
    "$PB" -c "Add :UIBackgroundModes:0 string audio" "$PLIST"
    echo "    Info.plist: 已在现有 UIBackgroundModes 追加 audio"
  fi
else
  "$PB" -c "Add :UIBackgroundModes array" "$PLIST"
  "$PB" -c "Add :UIBackgroundModes:0 string audio" "$PLIST"
  echo "    Info.plist: 已新建 UIBackgroundModes = [audio]"
fi

OBJECTS=()
for source in "${SOURCES[@]}"; do
  name="$(basename "$source" .c)"
  object="$WORK/${name}.o"
  xcrun --sdk iphoneos clang \
    -arch "$ARCH" \
    -isysroot "$SDK" \
    -miphoneos-version-min="$MIN_IOS" \
    -std=c11 -O2 -fPIC \
    -DCBC=0 -DCTR=0 -DECB=1 \
    -I "$CORE" \
    -Wall -Wextra \
    -c "$source" -o "$object"
  OBJECTS+=("$object")
done

rm -f "$OUT"
xcrun libtool -static -o "$OUT" "${OBJECTS[@]}"

echo "==> 产物"
ls -lh "$OUT"
xcrun lipo -info "$OUT"

# 符号自检：Swift 侧靠这几个符号链接，缺一个都会在链接期炸。
for symbol in sp_stream_open sp_stream_read sp_stream_seek sp_stream_size sp_stream_close; do
  if ! xcrun nm -gU "$OUT" 2>/dev/null | grep -q " _$symbol\$"; then
    echo "错误：libspcrypto.a 缺少符号 $symbol" >&2
    exit 1
  fi
done
echo "==> 符号校验通过（5 个 sp_stream_* 入口齐全）"
