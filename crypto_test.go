package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	client := NewClient()
	plaintext := []byte("Hello, AES-CTR mode!")

	keySizes := []int{16, 24, 32}
	for _, size := range keySizes {
		key := make([]byte, size)
		for i := range key {
			key[i] = byte(i)
		}

		encrypted, err := client.Encrypt(key, plaintext)
		if err != nil {
			t.Fatalf("key=%d Encrypt failed: %v", size*8, err)
		}

		// IV は先頭 16 バイトに埋め込まれるため、長さは BlockSize + len(plaintext)
		if len(encrypted) != aes.BlockSize+len(plaintext) {
			t.Errorf("key=%d encrypted length expected %d, got %d", size*8, aes.BlockSize+len(plaintext), len(encrypted))
		}

		decrypted, err := client.Decrypt(key, encrypted)
		if err != nil {
			t.Fatalf("key=%d Decrypt failed: %v", size*8, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("key=%d round-trip mismatch: expected %q, got %q", size*8, plaintext, decrypted)
		}
	}
}

func TestEncryptFromStringDecryptToStringRoundTrip(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x01}, 16)
	original := "テスト文字列 / test string"

	encrypted, err := client.EncryptFromString(key, original)
	if err != nil {
		t.Fatalf("EncryptFromString failed: %v", err)
	}

	result, err := client.DecryptToString(key, base64.StdEncoding.EncodeToString(encrypted))
	if err != nil {
		t.Fatalf("DecryptToString failed: %v", err)
	}

	if result != original {
		t.Errorf("round-trip mismatch: expected %q, got %q", original, result)
	}
}

func TestDecryptFromBase64RoundTrip(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0xAB}, 32)
	plaintext := []byte("binary-safe data: \x00\x01\x02\x03")

	encrypted, err := client.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := client.DecryptFromBase64(key, base64.StdEncoding.EncodeToString(encrypted))
	if err != nil {
		t.Fatalf("DecryptFromBase64 failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

func TestEncryptWithIVDecryptWithIVRoundTrip(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x10}, 16)
	iv := bytes.Repeat([]byte{0x20}, aes.BlockSize)
	plaintext := []byte("encrypt with explicit IV")

	encrypted, err := client.EncryptWithIV(key, plaintext, iv)
	if err != nil {
		t.Fatalf("EncryptWithIV failed: %v", err)
	}

	decrypted, err := client.DecryptWithIV(key, encrypted, iv)
	if err != nil {
		t.Fatalf("DecryptWithIV failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch: expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptWithIVFromStringDecryptWithIVToStringRoundTrip(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0xCC}, 24)
	iv := bytes.Repeat([]byte{0xDD}, aes.BlockSize)
	original := "IV付き暗号化テスト"

	encrypted, err := client.EncryptWithIVFromString(key, original, iv)
	if err != nil {
		t.Fatalf("EncryptWithIVFromString failed: %v", err)
	}

	result, err := client.DecryptWithIVToString(key, base64.StdEncoding.EncodeToString(encrypted), iv)
	if err != nil {
		t.Fatalf("DecryptWithIVToString failed: %v", err)
	}

	if result != original {
		t.Errorf("round-trip mismatch: expected %q, got %q", original, result)
	}
}

func TestDecryptWithIVFromBase64RoundTrip(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x55}, 32)
	iv := bytes.Repeat([]byte{0x66}, aes.BlockSize)
	plaintext := []byte("from base64 with iv")

	encrypted, err := client.EncryptWithIV(key, plaintext, iv)
	if err != nil {
		t.Fatalf("EncryptWithIV failed: %v", err)
	}

	decrypted, err := client.DecryptWithIVFromBase64(key, base64.StdEncoding.EncodeToString(encrypted), iv)
	if err != nil {
		t.Fatalf("DecryptWithIVFromBase64 failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch")
	}
}

func TestEncryptProducesDifferentCiphertextEachTime(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x01}, 16)
	plaintext := []byte("same plaintext")

	enc1, err := client.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt(1) failed: %v", err)
	}

	enc2, err := client.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt(2) failed: %v", err)
	}

	// ランダム IV を使うため、同じ平文でも暗号文は異なるはず
	if bytes.Equal(enc1, enc2) {
		t.Error("two encryptions of same plaintext produced identical ciphertext (IV not random)")
	}
}

func TestEncryptWithIVProducesDeterministicCiphertext(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, aes.BlockSize)
	plaintext := []byte("deterministic")

	enc1, err := client.EncryptWithIV(key, plaintext, iv)
	if err != nil {
		t.Fatalf("EncryptWithIV(1) failed: %v", err)
	}

	enc2, err := client.EncryptWithIV(key, plaintext, iv)
	if err != nil {
		t.Fatalf("EncryptWithIV(2) failed: %v", err)
	}

	// 同じ IV を使う場合、暗号文は一致する
	if !bytes.Equal(enc1, enc2) {
		t.Error("same key+iv+plaintext should produce identical ciphertext")
	}
}

func TestDecryptValueTooShort(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x01}, 16)

	_, err := client.Decrypt(key, make([]byte, aes.BlockSize-1))
	if err == nil {
		t.Error("expected error for value shorter than block size, got nil")
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	client := NewClient()

	_, err := client.Encrypt([]byte("invalidkey"), []byte("plaintext"))
	if err == nil {
		t.Error("expected error for invalid key size, got nil")
	}
}

func TestDecryptFromBase64InvalidBase64(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x01}, 16)

	_, err := client.DecryptFromBase64(key, "not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64 input, got nil")
	}
}

func TestDecryptToStringInvalidBase64(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x01}, 16)

	_, err := client.DecryptToString(key, strings.Repeat("X", 5)) // invalid base64 padding
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	client := NewClient()
	key := bytes.Repeat([]byte{0x01}, 16)

	encrypted, err := client.Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt(empty) failed: %v", err)
	}

	decrypted, err := client.Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("Decrypt(empty) failed: %v", err)
	}

	if !bytes.Equal(decrypted, []byte{}) {
		t.Errorf("expected empty slice, got %v", decrypted)
	}
}
