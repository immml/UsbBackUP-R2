package cred

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

// 凭据保护方式。
//
// 一台机器上能用的方式取决于操作系统：
//
//   - Windows 有 DPAPI（ProtectionDPAPIMachine），凭据与本机绑定，拷走解不开，
//     使用者不需要记任何口令——这是首选；
//   - Linux 没有等价的系统级密钥保管设施（内核 keyring 需要额外依赖，
//     且本项目只用标准库），所以走 ProtectionPassphrase：用口令派生密钥加密。
//
// 两种方式产出的**文件格式一致**，只有 protection 字段与 secret 的内容不同。
// 这一点很重要：解码器只要认 protection 就能读，不必按平台分叉文件格式。
const (
	// ProtectionPassphrase 表示敏感字段由口令派生的 AES-256-GCM 密钥保护。
	//
	// 派生参数（迭代次数、盐）与密文放在同一个 blob 里，文件自描述，
	// 将来调大迭代次数不会让旧文件读不出来。
	ProtectionPassphrase = "passphrase-aesgcm-v1"
	// ProtectionPlainFile 表示敏感字段**未加密**，只靠文件权限（0600）保护。
	//
	// 这是明示的降级选项：只有在无人值守场景下既没有 DPAPI 又不想让
	// 口令出现在任何自动读取的地方时才用。它的安全性等于"文件权限"，
	// 一旦被复制就完全失守——所以必须由调用方显式开启，绝不静默回退。
	ProtectionPlainFile = "plain-file-0600"
)

// 口令派生参数。
const (
	// pbkdf2Iterations 是 PBKDF2-SHA256 的迭代次数。
	//
	// 60 万次在本机约需数百毫秒——对"人手动跑一次的 CLI"是可接受的代价，
	// 而对离线爆破是显著的抬价。这个值只影响**新写入**的文件：
	// 迭代次数存在 blob 头部，旧文件仍按它自己记录的次数解密。
	pbkdf2Iterations = 600_000
	// pbkdf2KeyLen 是派生出的 AES-256 密钥长度。
	pbkdf2KeyLen = 32
	// saltLen / nonceLen 是随机盐与 GCM nonce 长度。
	saltLen  = 16
	nonceLen = 12
	// minPassphraseLen 是口令的最短长度。
	//
	// 口令是这里唯一的秘密来源，8 个字符是"不至于一句话就被猜到"的下限。
	// 真正的强度靠长度，提示语里会写清楚。
	minPassphraseLen = 8
)

// passBlobMagic 是口令保护 blob 的魔数，用于在解密前确认拿到了正确的东西。
var passBlobMagic = []byte("USBP")

// passBlobVersion 是 blob 结构版本。
const passBlobVersion = 1

// 口令保护相关错误。
var (
	// ErrPassphraseRequired 表示文件需要口令但调用方没有提供。
	ErrPassphraseRequired = errors.New("该凭据文件由口令保护，需要提供口令")
	// ErrPassphraseWrong 表示口令不对（或密文被篡改）。
	ErrPassphraseWrong = errors.New("口令不正确（或凭据文件已被篡改）")
	// ErrPassphraseTooShort 表示新口令太短。
	ErrPassphraseTooShort = fmt.Errorf("口令至少需要 %d 个字符", minPassphraseLen)
	// ErrPlainFileNotAllowed 表示文件是明文权限保护的，但调用方未显式许可。
	ErrPlainFileNotAllowed = errors.New("该凭据文件未加密（仅靠文件权限保护），" +
		"读取它需要显式开启 --allow-plain-cred")
	// ErrPlainFileTooOpen 表示明文凭据文件的权限比 0600 宽松。
	ErrPlainFileTooOpen = errors.New("明文凭据文件权限过宽（要求 0600）")
)

// aadFor 生成与保护方式绑定的附加认证数据。
//
// 绑定 FileFormat 与 protection 两个字段：把 passphrase 保护的内容塞进一个
// 声明为 plain-file 的文件里（或反之），GCM 校验会直接失败，
// 而不是让解密方按错误的语义去解释明文。
func aadFor(protection string) []byte {
	return []byte(FileFormat + "|" + protection)
}

// sealPassphrase 用口令派生的密钥封装敏感内容。
//
// blob 布局：magic(4) | version(1) | iterations(4, BE) | salt(16) | nonce(12) | 密文
func sealPassphrase(plain, passphrase []byte) ([]byte, error) {
	if len(passphrase) < minPassphraseLen {
		return nil, ErrPassphraseTooShort
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("生成随机盐失败: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("派生密钥失败: %w", err)
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 AES 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}

	head := make([]byte, 0, 4+1+4+saltLen+nonceLen)
	head = append(head, passBlobMagic...)
	head = append(head, passBlobVersion)
	head = binary.BigEndian.AppendUint32(head, pbkdf2Iterations)
	head = append(head, salt...)
	head = append(head, nonce...)

	ct := gcm.Seal(nil, nonce, plain, aadFor(ProtectionPassphrase))
	return append(head, ct...), nil
}

// openPassphrase 解开口令保护的内容。
func openPassphrase(blob, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrPassphraseRequired
	}
	const headLen = 4 + 1 + 4 + saltLen + nonceLen
	if len(blob) < headLen+16 { // 密文至少包含一个 GCM tag
		return nil, fmt.Errorf("%w: 数据长度不足", ErrPassphraseWrong)
	}
	if subtle.ConstantTimeCompare(blob[:4], passBlobMagic) != 1 {
		return nil, fmt.Errorf("%w: 缺少口令保护标识（文件被改写过？）", ErrPassphraseWrong)
	}
	if blob[4] != passBlobVersion {
		return nil, fmt.Errorf("口令保护 blob 版本 %d 不受支持（本程序支持 %d）",
			blob[4], passBlobVersion)
	}
	iter := int(binary.BigEndian.Uint32(blob[5:9]))
	if iter <= 0 || iter > 100_000_000 {
		return nil, fmt.Errorf("口令派生迭代次数异常（%d）", iter)
	}
	salt := blob[9 : 9+saltLen]
	nonce := blob[9+saltLen : headLen]
	ct := blob[headLen:]

	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, iter, pbkdf2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("派生密钥失败: %w", err)
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 AES 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ct, aadFor(ProtectionPassphrase))
	if err != nil {
		// 不区分"口令错"与"数据被篡改"——区分了就等于给爆破者一个预言机。
		return nil, ErrPassphraseWrong
	}
	return plain, nil
}

// checkPlainFilePerm 校验明文凭据文件的权限是否足够紧。
//
// Windows 上 os.FileMode 的权限位不可用（一律 0666/0444），所以只在
// 类 Unix 上检查。这不是"防护"，是"别把明文凭据放成 0644"的最低限度提醒。
func checkPlainFilePerm(path string, info os.FileInfo) error {
	if !enforceFilePerm() {
		return nil
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%w: %s 当前权限 %04o", ErrPlainFileTooOpen, path, mode)
	}
	return nil
}

// ErrUnsupportedPlatform 用于描述"该平台既没有 DPAPI，调用方也没给口令"。
//
// 注意这里不退化成明文：凭据文件的默认保护级别不该因为换了操作系统而悄悄下降。
func platformHint() string {
	return "本平台没有系统级密钥保管（Windows 上用 DPAPI），" +
		"请用 --cred-pass-file 指定口令文件，或设 USBBACKUP_R2_CRED_PASSPHRASE 环境变量"
}

// NormalizePassphrase 去除口令尾部的换行（从文件或 stdin 读来的常见形态）。
//
// 只去尾部 `\r\n`，不去空格：口令里的空格是有效字符，
// 而尾随换行几乎总是"读文件时带上的"，两者性质不同。
func NormalizePassphrase(p []byte) []byte {
	return []byte(strings.TrimRight(string(p), "\r\n"))
}
