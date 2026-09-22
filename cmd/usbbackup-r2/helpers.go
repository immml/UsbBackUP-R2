package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/immml/UsbBackUP-R2/internal/backup"
	"github.com/immml/UsbBackUP-R2/internal/cli"
	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/embedcfg"
	"github.com/immml/UsbBackUP-R2/internal/keystore"
)

// keystoreLoadPub 仅校验公钥可加载，用于 config-check。
func keystoreLoadPub(path string) (any, error) {
	if path == "" {
		return nil, errors.New("未配置公钥路径")
	}
	pub, err := keystore.LoadPublicKey(path)
	if err != nil {
		return nil, err
	}
	if pub.N.BitLen() < keystore.MinRSAKeyBits {
		return nil, fmt.Errorf("公钥仅 %d 位，低于下限 %d 位", pub.N.BitLen(), keystore.MinRSAKeyBits)
	}
	return pub, nil
}

// credSummary 读取凭据文件并给出一段**不含凭据材料**的摘要。
//
// 用于 config-check 与 probe 的"上传通道"一栏：现场排障第一个要回答的
// 问题就是"它到底连的是哪个桶、哪个前缀"，而这件事不该要求人去解密凭据文件。
func credSummary(cfg *config.Config) (string, error) {
	path, cands := credCandidates(cfg)
	if path == "" {
		if len(cands) == 0 {
			return "", errors.New("未配置凭据文件位置")
		}
		return "", fmt.Errorf("未找到凭据文件；已查找：%s", strings.Join(cands, "、"))
	}
	c, err := cred.Load(path, credAutoOpts(path)...)
	if err != nil {
		return "", fmt.Errorf("%s：%w", path, err)
	}
	defer c.Zero()
	return path + "\n    " + strings.ReplaceAll(c.Describe(), "\n", "\n    "), nil
}

// credAutoOpts 按凭据文件的实际保护方式组出读取选项。
//
// 客户端是无人值守运行的（服务形态连控制台都没有），读不出明文凭据就
// 等于安装时下发的凭据白做——所以这里按保护方式自动放行明文（见 cred.AutoOptions，
// 明文仍受 0600 权限校验约束）。需要人工确认的交互式命令
// （如 usbunseal-r2）仍保留 --allow-plain-cred 开关，不走这条路径。
func credAutoOpts(path string) []cred.Option {
	opts, _ := cred.AutoOptions(path)
	return opts
}

// credCandidates 暴露凭据候选路径，供诊断命令把"找过哪里"讲清楚。
//
// 与 backup 内部用的是同一套规则（同一份实现读两次文件代价极小，
// 而两份规则漂移会让诊断结论与现实不符——那是比不做诊断更糟的事）。
func credCandidates(cfg *config.Config) (string, []string) {
	return backup.ResolveCredentialPath(cfg)
}

// loadConfig 加载配置，优先级：内嵌配置（客户端模式）> 命令行 --config > 默认路径 > 内置默认。
//
// cfgPath 由 cli.ExtractGlobalFlags 在入口统一取出，此处不再自行解析参数。
//
// 客户端模式下配置已硬编码进可执行文件，**忽略外部配置文件与环境变量**：
// 客户端会运行在他人可控的机器上，若允许外部文件覆盖，
// "硬编码"就失去意义（改配置即可改行为）。
//
// 注意凭据**不在此列**：client.json 是独立文件（DPAPI 保护、可独立轮换），
// 它不在内嵌配置里，这是刻意的（见 internal/cred 的包注释）。
func loadConfig(cfgPath string, stderr io.Writer) (*config.Config, string, int) {
	if clientBuild.ok {
		if strings.TrimSpace(cfgPath) != "" {
			fmt.Fprintf(stderr, "提示：本程序为生成器产出的客户端，配置已内嵌，--config %s 已忽略。\n", cfgPath)
		}
		return clientBuild.cfg, "<内嵌于可执行文件>", cli.ExitOK
	}

	cfg, loaded, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return nil, "", cli.ExitRuntime
	}
	cfg.ApplyEnv()
	resolved := cfgPath
	if resolved == "" {
		resolved = config.DefaultConfigPath()
	}
	if !loaded {
		fmt.Fprintf(stderr, "提示：未找到配置文件 %s，本次使用内置默认值。\n", resolved)
	}
	return cfg, resolved, cli.ExitOK
}

// clientBuild 保存从自身可执行文件尾部读到的内嵌内容（客户端模式）。
var clientBuild struct {
	ok      bool
	cfg     *config.Config
	pub     *rsa.PublicKey
	name    string
	builtAt string
	builder string
}

// loadEmbedded 尝试读取自身可执行文件尾部的内嵌配置。
//
// 普通构建（非生成器产出）没有这个块，直接返回，行为与之前完全一致。
// 读取失败只警告不中断：配置损坏时宁可退回常规路径让人排障，
// 也不要静默使用一个来源不明的配置。
func loadEmbedded(stderr io.Writer) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	p, err := embedcfg.Read(exe)
	if err != nil {
		if !errors.Is(err, embedcfg.ErrNotEmbedded) {
			fmt.Fprintf(stderr, "警告：读取内嵌配置失败，已退回常规配置路径：%v\n", err)
		}
		return
	}
	cfg := config.Default()
	if len(p.ConfigJSON) > 0 {
		// 以默认值打底再覆盖，未写到的字段保留默认。
		if err := json.Unmarshal(p.ConfigJSON, cfg); err != nil {
			fmt.Fprintf(stderr, "警告：内嵌配置解析失败，已退回常规配置路径：%v\n", err)
			return
		}
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "警告：内嵌配置校验失败，已退回常规配置路径：%v\n", err)
		return
	}
	pub, err := keystore.ParsePublicKeyPEM([]byte(p.PublicKeyPEM))
	if err != nil {
		fmt.Fprintf(stderr, "警告：内嵌公钥解析失败，已退回常规配置路径：%v\n", err)
		return
	}
	clientBuild.ok = true
	clientBuild.cfg = cfg
	clientBuild.pub = pub
	clientBuild.name = p.ClientName
	clientBuild.builtAt = p.BuiltAt
	clientBuild.builder = p.BuilderVersion
}

// clientInfoLines 返回客户端模式的标识信息，用于启动摘要。
func clientInfoLines() []string {
	if !clientBuild.ok {
		return nil
	}
	lines := []string{"运行模式        = 客户端（配置与公钥已内嵌，忽略外部配置文件）"}
	if clientBuild.name != "" {
		lines = append(lines, fmt.Sprintf("客户端标识      = %s", clientBuild.name))
	}
	if clientBuild.builtAt != "" {
		lines = append(lines, fmt.Sprintf("生成时间        = %s", clientBuild.builtAt))
	}
	if clientBuild.builder != "" {
		lines = append(lines, fmt.Sprintf("生成器版本      = %s", clientBuild.builder))
	}
	return lines
}

// reportUploadChannel 在启动/诊断时把上传通道的可用性讲清楚（F-F06）。
//
// 凭据不可用**不是**启动失败：备份仍然要落本地，只是少了出站那一环。
// 但它必须是**显式可见**的——静默降级会让人以为"东西已经传上去了"。
func reportUploadChannel(cfg *config.Config, log interface {
	Info(string, ...any)
	Warn(string, ...any)
}) {
	if !cfg.Upload.Enabled {
		log.Info("上传未开启：产物只落本地", "dir", config.ExpandPath(cfg.OutputDir))
		return
	}
	path, cands := credCandidates(cfg)
	if path == "" {
		log.Warn("上传已开启但找不到凭据文件，本次仅保留本地产物",
			"expect", backup.CredentialFileName, "searched", strings.Join(cands, " | "))
		return
	}
	loadOpts, plainCred := cred.AutoOptions(path)
	c, err := cred.Load(path, loadOpts...)
	if err != nil {
		log.Warn("上传已开启但凭据不可用，本次仅保留本地产物", "path", path, "err", err)
		return
	}
	defer c.Zero()
	if plainCred {
		log.Warn("凭据文件未加密（仅靠文件权限保护），已自动放行读取",
			"path", path, "hint", "改用 dpapi-machine 或 passphrase 可消除此告警")
	}
	// 只在日志里放路由信息与不可逆的短标识，绝不放凭据材料（F-F07）。
	log.Info("上传通道可用",
		"cred_file", path,
		"endpoint", c.Endpoint,
		"bucket", c.Bucket,
		"prefix", c.EffectivePrefix(),
		"scope", c.EffectiveScope(),
		"cred", c.Redact())
}
