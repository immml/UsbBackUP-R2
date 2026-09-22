// Package cred 负责 Cloudflare R2 凭据的封装、落盘与读取。
//
// # 为什么不把凭据编译进客户端（决策 D-16）
//
// 原始需求要求把 Access Key ID / Secret Access Key 硬编码进客户端，再做
// AES + 密钥混淆 + garble 保护。这条被否决，理由不是"麻烦"，而是它解决不了
// 它声称要解决的问题：
//
//   - 客户端二进制会落到你可能不控制的机器上。AES 密钥也得写在同一份二进制里，
//     逆向者拿到的是"密钥 + 密文"两样齐全，混淆只是把提取成本从几分钟抬到几小时；
//   - 一旦提取，凭据就在别人手里，而它绑定的桶在你的账号下。轮换意味着
//     **重新编译并重新分发全部客户端**；
//   - 引入 garble 会破坏本项目"仅标准库、可离线构建"的硬约束。
//
// 改成外部凭据文件之后：轮换 = 换一个文件，不必重编译也不必重新分发；
// 并且可以直接用**只对该前缀有写权限**的受限 token——即使被提取，
// 攻击者也只能往你指定的前缀里写，读不到任何东西。
//
// # 保护方案
//
//   - 落盘为 JSON，其中**非敏感的路由信息**（endpoint / bucket / prefix / scope）
//     保持明文，便于运维直接查看与排障；
//   - 真正的凭据（Access Key ID / Secret Access Key / Session Token）单独序列化后
//     加密，以 base64 存进同一个 JSON；
//   - 运行时只在内存解密，用后尽力清零（Go 的字符串不可写，见 Zero 的说明）。
//
// 保护方式有三种（由 protection 字段区分，见 secretbox.go）：
//
//   - ProtectionDPAPIMachine：Windows 首选。凭据与本机绑定，换个机器（或重置系统）
//     就解不开，这正是想要的——文件被拷走也是一堆无用字节。代价是**跨平台不可用**：
//     在 Windows 上生成的 DPAPI 文件，拿到 Linux 上读不了。
//   - ProtectionPassphrase：跨平台。口令派生密钥（PBKDF2-SHA256 60 万次）后
//     AES-256-GCM 加密，迭代次数与盐写在密文头部，文件自描述。
//     **需要跨机器/跨系统用同一份凭据时，必须用这一档。**
//   - ProtectionPlainFile：明文，仅靠 0600 文件权限。只给无法提供口令的无人值守场景
//     兜底，必须显式开启；读取时也要显式许可，并会在类 Unix 上校验权限位。
//
// 无论哪一档，读写的都是同一个 JSON 结构——解码方只要看 protection
// 就知道该走哪条路，不必按操作系统分叉文件格式。
package cred

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/fsutil"
)

// FileFormat 是凭据文件的格式标识。
//
// 改格式必须同时改它，这样旧版本读到新文件时会明确拒绝，
// 而不是把字段解析成零值后"静默地用一个空凭据去连桶"。
const FileFormat = "usbbackup-r2-credentials/v1"

// SchemeVersion 是文件结构版本号，与 FileFormat 一起用于兼容性判断。
const SchemeVersion = 1

// ProtectionDPAPIMachine 表示敏感字段由 Windows DPAPI 机器范围保护。
const ProtectionDPAPIMachine = "dpapi-machine"

// FileName 是凭据文件的固定文件名。
//
// 它被**四个地方**共用：生成器产出、生成器装盘、客户端查找、解密器查找。
// 名字必须严格一致——现场最常见的问题就是"只拷了 exe 没拷 client.json"，
// 一旦哪一处写成了别的名字，客户端会静默退回"仅本地产物"，
// 而使用者以为东西已经传上去了。共用一个常量就是为了让改名只有一个入口。
const FileName = "client.json"

// 凭据用途（**指示性**，不是权限控制）。
//
// 真正约束权限的是 R2 那边的 token。这里记一笔现实情况，免得按不存在的
// 权限档位去配：
//
// R2 控制台能签发的长效 API token 只有四档——
//
//	Admin Read & Write / Admin Read only / Object Read & Write / Object Read only
//
// 也就是说：
//   - **没有"只写不读"这一档**。最小可达权限是 Object Read & Write，
//     它同时能读、能覆盖、能删除；
//   - 可限定的维度是**桶**，不是 **key 前缀**。想限前缀只能用
//     Temporary Access Credentials（`POST /accounts/{id}/r2/temp-access-credentials`，
//     支持 prefixes，但 TTL 上限 7 天），不适合无人值守常驻客户端。
//
// 于是"最小权限"在本平台上的落地形态是「Object Read & Write + 仅限目标桶」，
// 配套的运维手段只剩**定期轮换** token（换一份 client.json 就行，不必重编客户端）。
// 注意 R2 **不提供**对象版本控制，而这一档又具备删除能力 ⇒ 远端对象**没有防删兜底**，
// 这是使用前必须知情并自行承担的一点。
//
// Scope 这个字段本身只是给使用者的提示：拿错文件时能一眼看出用途不符。
const (
	// ScopeUpload 表示该凭据用于客户端上传。
	ScopeUpload = "upload"
	// ScopeDownload 表示该凭据用于解密器下载。
	ScopeDownload = "download"
	// ScopeBoth 表示读写共用一份凭据（不推荐）。
	ScopeBoth = "both"
)

// 错误。
var (
	// ErrUnsupportedPlatform 表示当前平台没有 DPAPI。
	ErrUnsupportedPlatform = errors.New("凭据保护仅支持 Windows（DPAPI）")
	// ErrBadProtection 表示文件声明的保护方式不受支持。
	ErrBadProtection = errors.New("凭据文件的保护方式不受支持")
	// ErrUnprotectFailed 表示 DPAPI 解密失败：文件被篡改，或来自其它机器/用户。
	ErrUnprotectFailed = errors.New("凭据解密失败（文件已损坏、被篡改，或不是在本机生成的）")
	// ErrMissingField 表示缺少必填字段。
	ErrMissingField = errors.New("凭据缺少必填字段")
)

// Credentials 是一份可用的连接凭据。
//
// 敏感字段用 []byte 而非 string 存储：Go 的 string 不可写，一旦变成字符串
// 就再也清不掉。这里至少在结构体层面保留了清零的可能。
type Credentials struct {
	// AccountID 是 Cloudflare 账户 ID。
	AccountID string
	// Bucket 是目标桶名。
	Bucket string
	// Endpoint 是 S3 API 端点，形如 https://<account_id>.r2.cloudflarestorage.com。
	Endpoint string
	// Region 是签名用区域，R2 固定为 auto。
	Region string
	// Prefix 是对象键前缀（会自动补一个结尾的 `/`）。
	Prefix string
	// Scope 是用途标识（upload / download / both）。
	Scope string
	// Label 是自由备注，便于辨认这份凭据是哪台机器/哪次部署的。
	Label string
	// CreatedAt 是生成时间（RFC3339）。
	CreatedAt string

	// AccessKeyID 是 token 的 Access Key ID。
	AccessKeyID []byte
	// SecretAccessKey 是 token 的 Secret Access Key。
	SecretAccessKey []byte
	// SessionToken 是可选临时凭据令牌。
	SessionToken []byte
}

// secretDoc 是被 DPAPI 保护的那部分内容。
//
// 单独抽一个结构体而不是加密整个文件，是为了让非敏感字段保持可读——
// 出问题时能直接 `type client.json` 看出它连的是哪个桶、哪个前缀，
// 而不用先解密。
type secretDoc struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

// fileDoc 是凭据文件在磁盘上的形态。
type fileDoc struct {
	Format        string `json:"format"`
	SchemeVersion int    `json:"scheme_version"`
	Protection    string `json:"protection"`
	AccountID     string `json:"account_id"`
	Bucket        string `json:"bucket"`
	Endpoint      string `json:"endpoint"`
	Region        string `json:"region"`
	Prefix        string `json:"prefix"`
	Scope         string `json:"scope"`
	Label         string `json:"label,omitempty"`
	CreatedAt     string `json:"created_at"`
	// Secret 是 base64(受保护且已认证的 blob)。
	// 具体内容取决于 Protection：DPAPI 密文，或口令派生的 AES-GCM 密文。
	Secret string `json:"secret,omitempty"`
	// SecretPlaintext 仅在 Protection = ProtectionPlainFile 时出现，是**明文**凭据。
	//
	// 刻意不复用 Secret 字段：字段名本身就得让人一眼看出"这里是没加密的"，
	// 而不是一段 base64 让人误以为有保护。
	SecretPlaintext *secretDoc `json:"secret_plaintext,omitempty"`
}

// NormalizePrefix 规范化对象键前缀：去掉首尾空白与开头的 `/`，
// 非空时保证以 `/` 结尾。
//
// 这样调用方可以直接做 `prefix + name` 拼接，不必各自记得补斜杠——
// 漏补一次就会把 `usb/` 和 `disk` 拼成 `usbdisk`，把对象散到别的"目录"下。
func NormalizePrefix(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	return p + "/"
}

// DefaultPrefix 是未配置前缀时的默认值。
const DefaultPrefix = "usb/"

// DefaultRegion 是 R2 的固定签名区域。
const DefaultRegion = "auto"

// DefaultScope 是默认用途。
const DefaultScope = ScopeUpload

// Validate 校验凭据的完整性与明显不合理之处。
func (c *Credentials) Validate() error {
	missing := func(name string) error {
		return fmt.Errorf("%w: %s", ErrMissingField, name)
	}
	if strings.TrimSpace(c.AccountID) == "" {
		return missing("account_id")
	}
	if strings.TrimSpace(c.Bucket) == "" {
		return missing("bucket")
	}
	if strings.TrimSpace(c.Endpoint) == "" {
		return missing("endpoint")
	}
	if err := ValidateEndpoint(c.Endpoint); err != nil {
		return err
	}
	if len(c.AccessKeyID) == 0 {
		return missing("access_key_id")
	}
	if len(c.SecretAccessKey) == 0 {
		return missing("secret_access_key")
	}
	switch c.Scope {
	case "", ScopeUpload, ScopeDownload, ScopeBoth:
	default:
		return fmt.Errorf("凭据的 scope 取值非法 %q（可用 upload/download/both）", c.Scope)
	}
	return nil
}

// ValidateEndpoint 校验端点写法。
//
// 只允许 https；唯一的例外是回环地址上的 http —— 这是给本地联调用的
// （本项目自带的假 S3 服务端就跑在 127.0.0.1 上）。允许远端 http 等于
// 把 Secret Access Key 与备份内容一并明文丢进网络，不能开这个口子。
func ValidateEndpoint(ep string) error {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return errors.New("endpoint 不能为空")
	}
	u, err := url.Parse(ep)
	if err != nil {
		return fmt.Errorf("endpoint 无法解析：%s", ep)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return fmt.Errorf("endpoint 只允许 https://（本机回环地址可用于联调）：%s", ep)
		}
	default:
		return fmt.Errorf("endpoint 必须以 https:// 开头：%s", ep)
	}
	if u.Host == "" {
		return fmt.Errorf("endpoint 缺少主机名：%s", ep)
	}
	// 端点只能是"协议 + 主机"。
	//
	// 这里必须**拒绝**而不是忽略路径：S3 客户端按 path-style 自己拼 `/<bucket>/<key>`，
	// 端点里的路径会被整段丢掉。静态检查不出来、请求也不会报错，只会打到另一个
	// 位置上去——"我明明写了桶名"和"实际请求去了哪"从此对不上。
	//
	// 桶名只有一个合法去处：bucket 字段。
	if p := strings.Trim(u.Path, "/"); p != "" {
		return fmt.Errorf("endpoint 不能带路径（当前带 %q）：桶名请填 bucket 字段，"+
			"S3 客户端会自己拼 /<bucket>/<key>；endpoint 只写协议与主机", "/"+p)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("endpoint 不能带查询串或锚点：%s", ep)
	}
	return nil
}

// EffectivePrefix 返回可直接用于拼接对象键的前缀。
func (c *Credentials) EffectivePrefix() string {
	if p := NormalizePrefix(c.Prefix); p != "" {
		return p
	}
	return DefaultPrefix
}

// EffectiveRegion 返回签名区域，默认 auto。
func (c *Credentials) EffectiveRegion() string {
	if r := strings.TrimSpace(c.Region); r != "" {
		return r
	}
	return DefaultRegion
}

// EffectiveScope 返回用途标识，默认 upload。
func (c *Credentials) EffectiveScope() string {
	if s := strings.TrimSpace(c.Scope); s != "" {
		return s
	}
	return DefaultScope
}

// Zero 尽力清零内存中的凭据材料。
//
// 说明（与 keystore 中的清零注释同一条）：Go 的 `string` 不可写，而
// http.Header、base64 等路径上难免产生临时字符串副本。这里能做到的是
// 清掉结构体自己持有的那份 []byte，其余副本只能等 GC 回收。
// 真正的防护依赖操作系统内存隔离与进程生命周期，不在此处兑现。
func (c *Credentials) Zero() {
	if c == nil {
		return
	}
	zeroBytes(c.AccessKeyID)
	zeroBytes(c.SecretAccessKey)
	zeroBytes(c.SessionToken)
	c.AccessKeyID = nil
	c.SecretAccessKey = nil
	c.SessionToken = nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Save 把凭据写入 path（原子替换，权限 0600）。
//
// 保护方式由可用条件决定，优先级：
//
//  1. 调用方给了口令（WithPassphrase / WithPassphraseFile / 环境变量）
//     → ProtectionPassphrase，跨平台可读（Windows 上生成的也能在 Linux 读）；
//  2. 平台有原生保管设施（Windows 的 DPAPI）→ ProtectionDPAPIMachine，
//     使用体验最好（无需记口令），但**换机器/换系统就读不了**；
//  3. 显式 WithForcePlainFile → ProtectionPlainFile（明文，仅 0600 保护）；
//  4. 都不满足 → 报错。绝不静默降级。
//
// 文件不存在其父目录时会自动创建，权限 0700。
func Save(path string, c Credentials, opts ...Option) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("凭据文件路径为空")
	}
	o := newOptions(opts)
	if c.Region == "" {
		c.Region = DefaultRegion
	}
	if c.Scope == "" {
		c.Scope = DefaultScope
	}
	if c.Prefix == "" {
		c.Prefix = DefaultPrefix
	}
	if strings.TrimSpace(c.CreatedAt) == "" {
		c.CreatedAt = time.Now().Format(time.RFC3339)
	}
	if err := c.Validate(); err != nil {
		return err
	}

	sd := secretDoc{
		AccessKeyID:     string(c.AccessKeyID),
		SecretAccessKey: string(c.SecretAccessKey),
		SessionToken:    string(c.SessionToken),
	}
	plain, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("序列化凭据失败: %w", err)
	}
	defer zeroBytes(plain)

	pass, passSrc, err := o.resolvePassphrase()
	if err != nil {
		return err
	}
	defer zeroBytes(pass)
	_ = passSrc

	// "给口令"和"要明文"是两条互斥的路，同时给出说明调用方写错了参数。
	// 不静默挑一个：无论挑哪个，都会有人以为自己的要求被满足了。
	if len(pass) > 0 && o.forcePlainFile {
		return errors.New("同时指定了口令与明文保护（WithForcePlainFile），语义冲突：" +
			"明文档不加密，口令无处可用")
	}

	doc := fileDoc{
		Format:        FileFormat,
		SchemeVersion: SchemeVersion,
		AccountID:     strings.TrimSpace(c.AccountID),
		Bucket:        strings.TrimSpace(c.Bucket),
		Endpoint:      strings.TrimSpace(c.Endpoint),
		Region:        c.Region,
		Prefix:        NormalizePrefix(c.Prefix),
		Scope:         c.Scope,
		Label:         strings.TrimSpace(c.Label),
		CreatedAt:     c.CreatedAt,
	}

	switch {
	case len(pass) > 0:
		blob, err := sealPassphrase(plain, pass)
		if err != nil {
			return err
		}
		defer zeroBytes(blob)
		doc.Protection = ProtectionPassphrase
		doc.Secret = base64.StdEncoding.EncodeToString(blob)

	// 显式的明文要求压过平台默认：调用方明确说了要什么，就该得到什么。
	// （顺序若反过来，Windows 上 WithForcePlainFile 会被 DPAPI 悄悄吃掉。）
	case o.forcePlainFile:
		doc.Protection = ProtectionPlainFile
		// 明文直接嵌成对象，而不是再 base64 一道——
		// base64 会让人误以为"多少有点保护"，字段名也更容易被忽略。
		plainDoc := sd
		doc.SecretPlaintext = &plainDoc

	case nativeProtection() != "":
		blob, err := nativeProtect(plain)
		if err != nil {
			return err
		}
		defer zeroBytes(blob)
		doc.Protection = nativeProtection()
		doc.Secret = base64.StdEncoding.EncodeToString(blob)

	default:
		return fmt.Errorf("无法确定凭据保护方式：%s", platformHint())
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化凭据文件失败: %w", err)
	}
	body = append(body, '\n')

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(fsutil.LongPath(dir), 0o700); err != nil {
			return fmt.Errorf("创建凭据目录失败: %w", err)
		}
	}
	tmp := path + ".part"
	if err := os.WriteFile(fsutil.LongPath(tmp), body, 0o600); err != nil {
		return fmt.Errorf("写入凭据失败: %w", err)
	}
	if err := os.Rename(fsutil.LongPath(tmp), fsutil.LongPath(path)); err != nil {
		_ = os.Remove(fsutil.LongPath(tmp))
		return fmt.Errorf("替换凭据文件失败: %w", err)
	}
	return nil
}

// Load 读取并解密凭据文件。
//
// 需要口令的文件（ProtectionPassphrase）会按 options.go 描述的优先级找口令；
// 找不到就返回 ErrPassphraseRequired，而不是给出一个含糊的"解密失败"。
func Load(path string, opts ...Option) (Credentials, error) {
	var c Credentials
	if strings.TrimSpace(path) == "" {
		return c, errors.New("凭据文件路径为空")
	}
	o := newOptions(opts)

	raw, err := os.ReadFile(fsutil.LongPath(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, fmt.Errorf("凭据文件不存在：%s", path)
		}
		return c, fmt.Errorf("读取凭据文件失败 %s: %w", path, err)
	}
	st, statErr := os.Stat(fsutil.LongPath(path))

	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return c, fmt.Errorf("解析凭据文件失败 %s（不是本工具生成的凭据文件？）: %w", path, err)
	}
	if doc.Format != FileFormat {
		return c, fmt.Errorf("%w: format=%q（期望 %q）", ErrBadProtection, doc.Format, FileFormat)
	}
	if doc.SchemeVersion != SchemeVersion {
		return c, fmt.Errorf("%w: scheme_version=%d（本程序支持 %d）",
			ErrBadProtection, doc.SchemeVersion, SchemeVersion)
	}

	var plain []byte
	switch doc.Protection {
	case ProtectionDPAPIMachine:
		if nativeProtection() == "" {
			return c, fmt.Errorf("该凭据文件由 Windows DPAPI 保护，与生成它的那台机器绑定，"+
				"只能在 Windows 上读取（当前不是 Windows）：%s", path)
		}
		blob, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(doc.Secret))
		if derr != nil || len(blob) == 0 {
			return c, fmt.Errorf("%w: secret 字段不是合法的 base64", ErrBadProtection)
		}
		plain, err = nativeUnprotect(blob)
		if err != nil {
			// 用 %w 保留哨兵错误，用 %v 附上系统原因：调用方需要能 errors.Is 判断
			// "这是解不开的凭据文件"，而不是去匹配一段本地化的系统错误文本。
			return c, fmt.Errorf("%w（%v）", ErrUnprotectFailed, err)
		}

	case ProtectionPassphrase:
		pass, _, perr := o.resolvePassphrase()
		if perr != nil {
			return c, perr
		}
		if len(pass) == 0 {
			return c, ErrPassphraseRequired
		}
		defer zeroBytes(pass)
		blob, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(doc.Secret))
		if derr != nil || len(blob) == 0 {
			return c, fmt.Errorf("%w: secret 字段不是合法的 base64", ErrBadProtection)
		}
		plain, err = openPassphrase(blob, pass)
		if err != nil {
			return c, err
		}

	case ProtectionPlainFile:
		if !o.allowPlainFile {
			return c, fmt.Errorf("%w: %s", ErrPlainFileNotAllowed, path)
		}
		if doc.SecretPlaintext == nil {
			return c, fmt.Errorf("%w: 声明为明文但缺少 secret_plaintext 字段", ErrBadProtection)
		}
		if statErr == nil {
			if perr := checkPlainFilePerm(path, st); perr != nil {
				return c, perr
			}
		}
		plain, err = json.Marshal(*doc.SecretPlaintext)
		if err != nil {
			return c, fmt.Errorf("还原明文凭据失败: %w", err)
		}

	default:
		return c, fmt.Errorf("%w: protection=%q", ErrBadProtection, doc.Protection)
	}
	defer zeroBytes(plain)

	var sd secretDoc
	if err := json.Unmarshal(plain, &sd); err != nil {
		return c, fmt.Errorf("%w: 解密后的内容不是合法凭据", ErrUnprotectFailed)
	}

	c = Credentials{
		AccountID:       doc.AccountID,
		Bucket:          doc.Bucket,
		Endpoint:        doc.Endpoint,
		Region:          doc.Region,
		Prefix:          doc.Prefix,
		Scope:           doc.Scope,
		Label:           doc.Label,
		CreatedAt:       doc.CreatedAt,
		AccessKeyID:     []byte(sd.AccessKeyID),
		SecretAccessKey: []byte(sd.SecretAccessKey),
		SessionToken:    []byte(sd.SessionToken),
	}
	zeroBytes([]byte(sd.SecretAccessKey))
	if err := c.Validate(); err != nil {
		c.Zero()
		return Credentials{}, fmt.Errorf("凭据文件 %s 内容不完整: %w", path, err)
	}
	return c, nil
}

// ProtectionOf 只读文件头，返回保护方式**而不解密**。
//
// 用途：命令行要在提示输入口令之前先知道"到底需不需要口令"。
// 否则会出现"先让人输口令，再告诉他这个文件是 DPAPI 的、在 Linux 上根本读不了"。
func ProtectionOf(path string) (string, error) {
	raw, err := os.ReadFile(fsutil.LongPath(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("凭据文件不存在：%s", path)
		}
		return "", fmt.Errorf("读取凭据文件失败 %s: %w", path, err)
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("解析凭据文件失败 %s: %w", path, err)
	}
	return doc.Protection, nil
}

// AutoOptions 按凭据文件的**实际保护方式**组出读取所需的选择项。
//
// 这是给"无人值守、无法交互"的客户端准备的：服务进程没有控制台，
// 弹不出 --allow-plain-cred 这种要求人确认的提示，可它又必须能读出
// 安装时下发的那份凭据。
//
// 语义边界（刻意收得很紧）：
//   - 只对 ProtectionPlainFile 追加 WithAllowPlainFile()，其余保护方式一律不动，
//     DPAPI 与口令加密的路径与从前完全一致；
//   - 明文仍然要过 Load 内部的 0600 权限校验（checkPlainFilePerm），
//     放宽的只是"要不要显式开关"这一道，不是"文件权限"那一层；
//   - 返回 plain=true 让调用方能在日志/横幅里**明说这是明文凭据**，
//     不允许静默——放行不等于假装它没发生过。
//
// 读不出保护方式时不追加任何选项，交给 Load 去报具体错误。
func AutoOptions(path string) (opts []Option, plain bool) {
	p, err := ProtectionOf(path)
	if err != nil {
		return nil, false
	}
	if p == ProtectionPlainFile {
		return []Option{WithAllowPlainFile()}, true
	}
	return nil, false
}

// NeedsPassphrase 判断读该文件是否需要口令（不读取内容以外的任何东西）。
func NeedsPassphrase(path string) (bool, error) {
	p, err := ProtectionOf(path)
	if err != nil {
		return false, err
	}
	return p == ProtectionPassphrase, nil
}

// ProtectionNote 把一个 protection 值翻译成一句给人看的说明。
//
// 集中在这里是因为"DPAPI 的凭据在 Linux 上读不了"这件事，
// 生成器、解密器的 config 命令都要说一遍；抄三遍早晚会有一处说漏，
// 而说漏的那一处恰好会让人把凭据拷到服务器上才发现读不了。
func ProtectionNote(protection string) string {
	switch protection {
	case ProtectionDPAPIMachine:
		return "DPAPI（机器范围）—— 只有生成它的那台 Windows 机器能读，换机器/重装系统后解不开"
	case ProtectionPassphrase:
		return "口令加密（PBKDF2-SHA256 + AES-256-GCM）—— 跨平台可读，凭口令解密"
	case ProtectionPlainFile:
		return "**未加密**（明文）—— 只有 0600 文件权限这一层保护"
	case "":
		return "未知（文件不存在或无法解析）"
	default:
		return protection + "（本程序不认识这个值，可能由更新的版本生成）"
	}
}

// Describe 返回一段**不含任何凭据材料**的摘要，可直接打印到终端或写日志。
func (c *Credentials) Describe() string {
	scopeNote := map[string]string{
		ScopeUpload:   "上传（应为仅写权限的 token）",
		ScopeDownload: "下载（需要读/列举权限）",
		ScopeBoth:     "读写共用（不推荐：客户端持有读取权限）",
	}[c.EffectiveScope()]
	if scopeNote == "" {
		scopeNote = c.EffectiveScope()
	}
	return strings.Join([]string{
		fmt.Sprintf("端点       : %s", c.Endpoint),
		fmt.Sprintf("桶 / 前缀  : %s / %s", c.Bucket, c.EffectivePrefix()),
		fmt.Sprintf("签名区域   : %s", c.EffectiveRegion()),
		fmt.Sprintf("凭据用途   : %s", scopeNote),
		fmt.Sprintf("凭据长度   : access_key_id %d 字符，secret %d 字符",
			len(c.AccessKeyID), len(c.SecretAccessKey)),
	}, "\n")
}

// Redact 返回一个必然不包含凭据内容的短标识，用于日志。
//
// 只暴露 Access Key ID 的**前 4 位**：足以在多个 token 之间区分，
// 又不足以拿去做什么——Cloudflare 的 access key id 是 32 位十六进制，
// 前 4 位的信息量是 16 bit。
func (c *Credentials) Redact() string {
	if len(c.AccessKeyID) < 4 {
		return "(凭据长度异常)"
	}
	return string(c.AccessKeyID[:4]) + "…"
}
