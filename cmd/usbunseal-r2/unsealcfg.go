package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/version"
)

// UnsealConfigFormat 是解密器配置文件的格式标识。
//
// 与凭据文件同理：改结构必须同时改它，否则旧版本会把新文件解析出一堆零值，
// 然后"用一个空配置去连远端"，而错误信息离真相很远。
const UnsealConfigFormat = "usbbackup-r2-unseal/v1"

// UnsealConfigSchemeVersion 是结构版本号。
const UnsealConfigSchemeVersion = 1

// unsealConfig 是解密器的运行参数。
//
// 存在的理由很实际：解密器是**人反复敲**的命令。每次都写
//
//	--cred ~/.config/usbbackup-r2/client.json --key ~/.config/... --out ~/restore --pass-file ...
//
// 一定会有人漏参数，而漏 --out 会解到当前目录、漏 --key 要白跑一趟。
// 把固定项写进 cfg 之后，日常命令就退化成 `usbunseal-r2 pull`。
//
// 分层优先级刻意做成最简单的形态：**配置文件写 flag 的默认值**。
// 即先读 cfg，再用 cfg 的值去构造 FlagSet；命令行给了什么就覆盖什么。
// 这样就不需要"某个 flag 是否被显式设置"这类判断，也不会有
// "给了空值算不算给了"的歧义。
type unsealConfig struct {
	Format        string `json:"format"`
	SchemeVersion int    `json:"scheme_version"`

	// 远端路由。留空则用凭据文件里记的——凭据才是权威来源，
	// 这里只在"一份凭据要多前缀并存"时才需要覆盖。
	Endpoint string `json:"endpoint,omitempty"`
	Bucket   string `json:"bucket,omitempty"`
	Prefix   string `json:"prefix,omitempty"`

	// CredFile 是 R2 凭据文件路径。
	CredFile string `json:"cred_file,omitempty"`
	// CredPassFile 是凭据文件口令的来源（首行）。
	CredPassFile string `json:"cred_pass_file,omitempty"`
	// AllowPlainCred 允许读取未加密的凭据文件（仅 0600 保护）。
	AllowPlainCred bool `json:"allow_plain_cred,omitempty"`

	// KeyFile 是解密私钥路径（PKCS#8 / PKCS#1 PEM）。
	KeyFile string `json:"key_file,omitempty"`
	// KeyPassFile 是私钥口令来源（首行）；空则按需交互提示。
	KeyPassFile string `json:"key_pass_file,omitempty"`

	// OutDir 是解压目标目录。
	OutDir string `json:"out_dir,omitempty"`

	// 行为开关。
	SkipExisting  bool `json:"skip_existing"`
	KeepContainer bool `json:"keep_container,omitempty"`
	DeleteRemote  bool `json:"delete_remote,omitempty"`
	Limit         int  `json:"limit,omitempty"`
}

// DefaultUnsealConfig 返回内置默认配置。
//
// 配置目录用 os.UserConfigDir()：Linux 给 $XDG_CONFIG_HOME 或 ~/.config，
// Windows 给 %AppData%。手写这两个分支容易在某一侧漏掉 XDG，
// 交给标准库更稳。
func DefaultUnsealConfig() unsealConfig {
	base := defaultConfigDir()
	return unsealConfig{
		Format:        UnsealConfigFormat,
		SchemeVersion: UnsealConfigSchemeVersion,
		Prefix:        cred.DefaultPrefix,
		CredFile:      filepath.Join(base, cred.FileName),
		KeyFile:       filepath.Join(base, "usbbackup-r2.key.pem"),
		OutDir:        filepath.Join(homeDir(), "usbbackup-restore"),
		SkipExisting:  true,
	}
}

// defaultConfigDir 返回配置文件所在目录。
func defaultConfigDir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, version.AppName)
	}
	// UserConfigDir 在极少数环境下会失败（既没有 HOME 也没有 XDG）。
	// 退回临时目录而不是当前目录：配置里带着凭据与私钥路径，
	// 落到当前目录最容易跟着某个项目的 git 一起被提交出去。
	return filepath.Join(os.TempDir(), version.AppName)
}

// homeDir 返回 home 目录，取不到时退化为当前目录。
func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "."
}

// DefaultUnsealConfigPath 返回默认配置文件路径。
func DefaultUnsealConfigPath() string {
	return filepath.Join(defaultConfigDir(), "unseal.json")
}

// LoadUnsealConfig 读取配置文件并与内置默认值合并。
//
// 显式给出的路径读不到就是错误：人明确指了文件，静默用默认配置会让他
// 以为配置生效了。默认路径读不到则返回纯默认值（首次运行本来就没有文件）。
func LoadUnsealConfig(path string, explicit bool) (unsealConfig, error) {
	cfg := DefaultUnsealConfig()
	if strings.TrimSpace(path) == "" {
		path = DefaultUnsealConfigPath()
	}
	raw, err := os.ReadFile(fsutil.LongPath(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if explicit {
				return cfg, fmt.Errorf("配置文件不存在：%s", path)
			}
			return cfg, nil
		}
		return cfg, fmt.Errorf("读取配置文件失败 %s: %w", path, err)
	}

	// 先解析成「键 -> 原始值」，这样能精确区分"字段没写"与"字段写成了 false"。
	// 直接反序列化到结构体做不到这一点，而 skip_existing 这种
	// 「默认 true」的开关恰恰需要它。
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return cfg, fmt.Errorf("解析配置文件失败 %s: %w", path, err)
	}

	if err := checkConfigHeader(fields, path); err != nil {
		return cfg, err
	}

	// 只有出现在文件里的键才覆盖默认值。
	decode := func(key string, dst any) error {
		v, ok := fields[key]
		if !ok {
			return nil
		}
		if err := json.Unmarshal(v, dst); err != nil {
			return fmt.Errorf("配置字段 %s 类型不对 %s: %w", key, path, err)
		}
		return nil
	}
	for _, f := range []struct {
		key string
		dst any
	}{
		{"endpoint", &cfg.Endpoint},
		{"bucket", &cfg.Bucket},
		{"prefix", &cfg.Prefix},
		{"cred_file", &cfg.CredFile},
		{"cred_pass_file", &cfg.CredPassFile},
		{"allow_plain_cred", &cfg.AllowPlainCred},
		{"key_file", &cfg.KeyFile},
		{"key_pass_file", &cfg.KeyPassFile},
		{"out_dir", &cfg.OutDir},
		{"skip_existing", &cfg.SkipExisting},
		{"keep_container", &cfg.KeepContainer},
		{"delete_remote", &cfg.DeleteRemote},
		{"limit", &cfg.Limit},
	} {
		if err := decode(f.key, f.dst); err != nil {
			return DefaultUnsealConfig(), err
		}
	}

	// 全局开关按文档默认值补齐（旧文件里没有这两项）。
	if cfg.Format == "" {
		cfg.Format = UnsealConfigFormat
	}
	if cfg.SchemeVersion == 0 {
		cfg.SchemeVersion = UnsealConfigSchemeVersion
	}
	if strings.TrimSpace(cfg.Prefix) == "" {
		cfg.Prefix = cred.DefaultPrefix
	}
	return cfg, nil
}

// checkConfigHeader 校验 format / scheme_version 两个头字段。
//
// 分开检查而不复用上面的 decode：这两个字段的错必须报出来，
// 不能让它们的值静默留在默认状态。
func checkConfigHeader(fields map[string]json.RawMessage, path string) error {
	if v, ok := fields["format"]; ok {
		var f string
		if err := json.Unmarshal(v, &f); err != nil {
			return fmt.Errorf("配置字段 format 类型不对 %s: %w", path, err)
		}
		if f != UnsealConfigFormat {
			return fmt.Errorf("配置文件格式不受支持：format=%q（期望 %q）", f, UnsealConfigFormat)
		}
	}
	if v, ok := fields["scheme_version"]; ok {
		var n int
		if err := json.Unmarshal(v, &n); err != nil {
			return fmt.Errorf("配置字段 scheme_version 类型不对 %s: %w", path, err)
		}
		if n != UnsealConfigSchemeVersion {
			return fmt.Errorf("配置文件版本不受支持：scheme_version=%d（本程序支持 %d）",
				n, UnsealConfigSchemeVersion)
		}
	}
	return nil
}

// SaveUnsealConfig 写入配置文件（0600，父目录 0700）。
func SaveUnsealConfig(path string, cfg unsealConfig, force bool) error {
	if !force {
		if _, err := os.Stat(fsutil.LongPath(path)); err == nil {
			return fmt.Errorf("配置文件已存在：%s（加 --force 覆盖）", path)
		}
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(fsutil.LongPath(dir), 0o700); err != nil {
			return fmt.Errorf("创建配置目录失败: %w", err)
		}
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.WriteFile(fsutil.LongPath(path), body, 0o600); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	return nil
}

// Describe 打印生效配置（**不含任何凭据材料**）。
//
// cfgPath 与实际加载来源分开报：当用户改了默认位置的文件却发现"没生效"时，
// 第一件要确认的事就是工具到底读了哪个文件。
func (c unsealConfig) Describe(w io.Writer, cfgPath, cfgSource string) {
	fmt.Fprintf(w, "配置文件  : %s（%s）\n", cfgPath, cfgSource)
	blank := func(label, v string) {
		if strings.TrimSpace(v) == "" {
			v = "(未设置，用凭据里的值)"
		}
		fmt.Fprintf(w, "%-10s: %s\n", label, v)
	}
	blank("端点", c.Endpoint)
	blank("桶", c.Bucket)
	blank("前缀", c.Prefix)
	fmt.Fprintf(w, "凭据文件  : %s\n", c.CredFile)
	if c.CredPassFile != "" {
		fmt.Fprintf(w, "凭据口令  : %s\n", c.CredPassFile)
	} else {
		fmt.Fprintln(w, "凭据口令  : 未配置（需要时交互提示）")
	}
	if c.AllowPlainCred {
		fmt.Fprintln(w, "明文凭据  : 允许（该凭据未加密，仅靠文件权限保护）")
	}
	fmt.Fprintf(w, "私钥文件  : %s\n", c.KeyFile)
	if c.KeyPassFile != "" {
		fmt.Fprintf(w, "私钥口令  : %s\n", c.KeyPassFile)
	} else {
		fmt.Fprintln(w, "私钥口令  : 未配置（需要时交互提示）")
	}
	fmt.Fprintf(w, "解压目录  : %s\n", c.OutDir)
	fmt.Fprintf(w, "跳过已存在: %v\n", c.SkipExisting)
	fmt.Fprintf(w, "保留容器  : %v\n", c.KeepContainer)
	fmt.Fprintf(w, "删远端对象: %v\n", c.DeleteRemote)
}

// expand 展开配置里的路径（支持 ~ 与 %VAR%）。
func expand(p string) string {
	if strings.TrimSpace(p) == "" {
		return ""
	}
	return config.ExpandPath(p)
}
