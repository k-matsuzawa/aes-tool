package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	case "encrypt-with-iv":
		runEncryptWithIV(os.Args[2:])
	case "decrypt-with-iv":
		runDecryptWithIV(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: aes-tool <command> [options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  encrypt           AES-CTR 暗号化（IV はランダム生成）")
	fmt.Fprintln(os.Stderr, "  decrypt           AES-CTR 復号")
	fmt.Fprintln(os.Stderr, "  encrypt-with-iv   AES-CTR 暗号化（IV を指定）")
	fmt.Fprintln(os.Stderr, "  decrypt-with-iv   AES-CTR 復号（IV を指定）")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "共通オプション:")
	fmt.Fprintln(os.Stderr, "  --key    hex 文字列（AES-128: 32文字, AES-192: 48文字, AES-256: 64文字）")
	fmt.Fprintln(os.Stderr, "  --value  base64 エンコード済み文字列")
	fmt.Fprintln(os.Stderr, "  --iv     hex 文字列（16バイト = 32文字）※encrypt-with-iv / decrypt-with-iv のみ")
	fmt.Fprintln(os.Stderr, "  --output 出力先ファイルパス（省略時は標準出力）")
}

// parseKey は hex 文字列をデコードし、AES キーとして有効な長さか検証する。
func parseKey(keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("--key は hex 文字列で指定してください: %w", err)
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("--key は 16, 24, 32 バイト（32/48/64 hex 文字）のいずれかにしてください（現在: %d バイト）", len(key))
	}
	return key, nil
}

// parseIV は hex 文字列をデコードし、16 バイトの IV として検証する。
func parseIV(ivHex string) ([]byte, error) {
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("--iv は hex 文字列で指定してください: %w", err)
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("--iv は 16 バイト（32 hex 文字）にしてください（現在: %d バイト）", len(iv))
	}
	return iv, nil
}

// parseValue は base64 文字列をデコードしてバイト列を返す。
func parseValue(valueBase64 string) ([]byte, error) {
	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		return nil, fmt.Errorf("--value は base64 エンコード済み文字列で指定してください: %w", err)
	}
	return value, nil
}

// writeEncrypted は暗号文バイト列を base64 エンコードして出力する。
func writeEncrypted(data []byte, outputPath string) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	if outputPath == "" {
		fmt.Println(encoded)
		return nil
	}
	return os.WriteFile(outputPath, []byte(encoded), 0600)
}

// writePlaintext は復号済みバイト列を出力する。
func writePlaintext(data []byte, outputPath string) error {
	if outputPath == "" {
		fmt.Printf("%s\n", data)
		return nil
	}
	return os.WriteFile(outputPath, data, 0600)
}

func runEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	keyHex := fs.String("key", "", "AES キー（hex 文字列）")
	valueBase64 := fs.String("value", "", "暗号化する平文（base64 エンコード済み）")
	outputPath := fs.String("output", "", "出力先ファイルパス（省略時は標準出力）")
	fs.Parse(args) //nolint:errcheck

	if *keyHex == "" || *valueBase64 == "" {
		fmt.Fprintln(os.Stderr, "エラー: --key と --value は必須です")
		fs.Usage()
		os.Exit(1)
	}

	key, err := parseKey(*keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %v\n", err)
		os.Exit(1)
	}

	value, err := parseValue(*valueBase64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %v\n", err)
		os.Exit(1)
	}

	client := NewClient()
	encrypted, err := client.Encrypt(key, value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: 暗号化に失敗しました: %v\n", err)
		os.Exit(1)
	}

	if err := writeEncrypted(encrypted, *outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "エラー: 出力に失敗しました: %v\n", err)
		os.Exit(1)
	}
}

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	keyHex := fs.String("key", "", "AES キー（hex 文字列）")
	valueBase64 := fs.String("value", "", "復号する暗号文（base64 エンコード済み）")
	outputPath := fs.String("output", "", "出力先ファイルパス（省略時は標準出力）")
	fs.Parse(args) //nolint:errcheck

	if *keyHex == "" || *valueBase64 == "" {
		fmt.Fprintln(os.Stderr, "エラー: --key と --value は必須です")
		fs.Usage()
		os.Exit(1)
	}

	key, err := parseKey(*keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %v\n", err)
		os.Exit(1)
	}

	client := NewClient()
	decrypted, err := client.DecryptFromBase64(key, *valueBase64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: 復号に失敗しました: %v\n", err)
		os.Exit(1)
	}

	if err := writePlaintext(decrypted, *outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "エラー: 出力に失敗しました: %v\n", err)
		os.Exit(1)
	}
}

func runEncryptWithIV(args []string) {
	fs := flag.NewFlagSet("encrypt-with-iv", flag.ExitOnError)
	keyHex := fs.String("key", "", "AES キー（hex 文字列）")
	valueBase64 := fs.String("value", "", "暗号化する平文（base64 エンコード済み）")
	ivHex := fs.String("iv", "", "IV（hex 文字列、16バイト）")
	outputPath := fs.String("output", "", "出力先ファイルパス（省略時は標準出力）")
	fs.Parse(args) //nolint:errcheck

	if *keyHex == "" || *valueBase64 == "" || *ivHex == "" {
		fmt.Fprintln(os.Stderr, "エラー: --key, --value, --iv はすべて必須です")
		fs.Usage()
		os.Exit(1)
	}

	key, err := parseKey(*keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %v\n", err)
		os.Exit(1)
	}

	iv, err := parseIV(*ivHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %v\n", err)
		os.Exit(1)
	}

	value, err := parseValue(*valueBase64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %v\n", err)
		os.Exit(1)
	}

	client := NewClient()
	encrypted, err := client.EncryptWithIV(key, value, iv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: 暗号化に失敗しました: %v\n", err)
		os.Exit(1)
	}

	if err := writeEncrypted(encrypted, *outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "エラー: 出力に失敗しました: %v\n", err)
		os.Exit(1)
	}
}

func runDecryptWithIV(args []string) {
	fs := flag.NewFlagSet("decrypt-with-iv", flag.ExitOnError)
	keyHex := fs.String("key", "", "AES キー（hex 文字列）")
	valueBase64 := fs.String("value", "", "復号する暗号文（base64 エンコード済み）")
	ivHex := fs.String("iv", "", "IV（hex 文字列、16バイト）")
	outputPath := fs.String("output", "", "出力先ファイルパス（省略時は標準出力）")
	fs.Parse(args) //nolint:errcheck

	if *keyHex == "" || *valueBase64 == "" || *ivHex == "" {
		fmt.Fprintln(os.Stderr, "エラー: --key, --value, --iv はすべて必須です")
		fs.Usage()
		os.Exit(1)
	}

	key, err := parseKey(*keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %v\n", err)
		os.Exit(1)
	}

	iv, err := parseIV(*ivHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: %v\n", err)
		os.Exit(1)
	}

	client := NewClient()
	decrypted, err := client.DecryptWithIVFromBase64(key, *valueBase64, iv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "エラー: 復号に失敗しました: %v\n", err)
		os.Exit(1)
	}

	if err := writePlaintext(decrypted, *outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "エラー: 出力に失敗しました: %v\n", err)
		os.Exit(1)
	}
}
