# aes-tool

AES-CTR モードによる暗号化・復号を行うコマンドラインツールです。

## 必要環境

- Go 1.21 以上

## ビルド

```bash
go build -o aes-tool .
```

## コマンド一覧

| コマンド | 説明 |
| --- | --- |
| `encrypt` | AES-CTR で暗号化（IV はランダム生成） |
| `decrypt` | AES-CTR で復号 |
| `encrypt-with-iv` | AES-CTR で暗号化（IV を明示指定。出力に含めず） |
| `decrypt-with-iv` | AES-CTR で復号（IV を明示指定） |

## オプション

| オプション | 必須 | 説明 |
| --- | --- | --- |
| `--key` | ✓ | AES キー（hex 文字列）。AES-128: 32文字、AES-192: 48文字、AES-256: 64文字 |
| `--value` | ✓ | 暗号化する平文または復号する暗号文（base64 エンコード済み） |
| `--iv` | ✓ ※1 | IV（hex 文字列、16バイト = 32文字） |
| `--output` | - | 出力先ファイルパス。省略時は標準出力に表示 |

※1 `encrypt-with-iv` / `decrypt-with-iv` コマンドでのみ必須

## 使い方

### 1. 暗号化（IV ランダム生成）

```bash
# 平文を base64 エンコードしてから渡す
PLAINTEXT_B64=$(echo -n "Hello, World!" | base64)

aes-tool encrypt \
  --key 0123456789abcdef0123456789abcdef \
  --value "$PLAINTEXT_B64"
# → 暗号文が base64 エンコードされて標準出力に表示される

# ファイルに出力する場合
aes-tool encrypt \
  --key 0123456789abcdef0123456789abcdef \
  --value "$PLAINTEXT_B64" \
  --output encrypted.b64
```

### 2. 復号

```bash
aes-tool decrypt \
  --key 0123456789abcdef0123456789abcdef \
  --value "<encrypt コマンドの出力>"
# → 復号された平文が標準出力に表示される

# ファイルに出力する場合
aes-tool decrypt \
  --key 0123456789abcdef0123456789abcdef \
  --value "<encrypt コマンドの出力>" \
  --output decrypted.txt
```

### 3. 暗号化（IV 指定）

```bash
PLAINTEXT_B64=$(echo -n "Hello, World!" | base64)

aes-tool encrypt-with-iv \
  --key 0123456789abcdef0123456789abcdef \
  --value "$PLAINTEXT_B64" \
  --iv 00112233445566778899aabbccddeeff
```

### 4. 復号（IV 指定）

```bash
aes-tool decrypt-with-iv \
  --key 0123456789abcdef0123456789abcdef \
  --value "<encrypt-with-iv コマンドの出力>" \
  --iv 00112233445566778899aabbccddeeff
```

## 仕様

- 暗号方式: AES-CTR（Counter モード）
- 鍵長: 16 バイト（AES-128）、24 バイト（AES-192）、32 バイト（AES-256）
- IV: 16 バイト固定。`encrypt` では毎回ランダム生成され、暗号文の先頭 16 バイトに付与されます
- 入力値（`--value`）: base64 エンコード済みバイト列
- 暗号化出力: `[IV (16 bytes)] + [暗号文]` を base64 エンコードした文字列
- 復号出力: 元の平文バイト列（テキストの場合はそのまま表示）

## テスト

```bash
go test ./...
```

## ライセンス

MIT License
