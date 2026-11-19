// gen-signing-key 生成并操作 mnagent 更新签名用的 Ed25519 密钥。
//
// 只依赖 Go 标准库：
//
//	go run ./scripts/gen-signing-key.go                       # 生成 signing-private.key / signing-public.key
//	go run ./scripts/gen-signing-key.go -mode public -key signing-private.key
//	go run ./scripts/gen-signing-key.go -mode sign -key signing-private.key -in file.sha256 -out file.sha256.sig
//
// 私钥文件内容是 64 字节 Ed25519 私钥的 base64，必须保存在 GitHub Actions Secret
// （MNAGENT_SIGNING_PRIVATE_KEY）中，绝不能提交到仓库。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	mode := flag.String("mode", "generate", "操作模式：generate / public / sign")
	privatePath := flag.String("private", "signing-private.key", "生成模式：私钥输出路径")
	publicPath := flag.String("public", "signing-public.key", "生成模式：公钥输出路径")
	keyPath := flag.String("key", "signing-private.key", "public/sign 模式：私钥文件路径")
	inPath := flag.String("in", "", "sign 模式：待签名文件")
	outPath := flag.String("out", "", "sign 模式：签名输出路径（默认 <in>.sig）")
	flag.Parse()

	switch strings.ToLower(strings.TrimSpace(*mode)) {
	case "generate":
		if err := generate(*privatePath, *publicPath); err != nil {
			fail(err)
		}
	case "public":
		priv, err := loadPrivateKey(*keyPath)
		if err != nil {
			fail(err)
		}
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
	case "sign":
		if *inPath == "" {
			fail(fmt.Errorf("sign 模式必须指定 -in"))
		}
		priv, err := loadPrivateKey(*keyPath)
		if err != nil {
			fail(err)
		}
		data, err := os.ReadFile(*inPath)
		if err != nil {
			fail(fmt.Errorf("读取待签名文件失败：%w", err))
		}
		out := *outPath
		if out == "" {
			out = *inPath + ".sig"
		}
		sig := ed25519.Sign(priv, data)
		if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
			fail(fmt.Errorf("写入签名失败：%w", err))
		}
		fmt.Fprintf(os.Stderr, "已签名 %s -> %s\n", *inPath, out)
	default:
		fail(fmt.Errorf("未知 -mode：%q（可选 generate/public/sign）", *mode))
	}
}

func generate(privatePath, publicPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("生成密钥失败：%w", err)
	}
	if err := os.WriteFile(privatePath, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return fmt.Errorf("写入私钥失败：%w", err)
	}
	if err := os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return fmt.Errorf("写入公钥失败：%w", err)
	}
	fmt.Fprintf(os.Stderr, "已生成 %s（0600）与 %s（0644）\n", privatePath, publicPath)
	fmt.Fprintf(os.Stderr, "请把私钥内容保存为 GitHub Actions Secret MNAGENT_SIGNING_PRIVATE_KEY，并删除本地私钥文件。\n")
	fmt.Fprintf(os.Stderr, "内置公钥的 ldflags：-X github.com/mengnanquq/mnagent/internal/updater.SigningPublicKeyBase64=%s\n",
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取私钥失败：%w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("私钥不是合法 base64：%w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("私钥长度非法：期望 %d 字节，实际 %d", ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen-signing-key:", err)
	os.Exit(1)
}
