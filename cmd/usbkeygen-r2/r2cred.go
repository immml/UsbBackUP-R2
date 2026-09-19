package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/cli"
	"github.com/immml/UsbBackUP-R2/internal/config"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/fsutil"
	"github.com/immml/UsbBackUP-R2/internal/r2"
	"github.com/immml/UsbBackUP-R2/internal/version"
)

// DefaultCredentialFileName 是生成器产出的凭据文件名。
//
// 必须与客户端、解密器查找的名字一致（同一个常量），
// 否则现场"只拷了 client.exe"会因为找不到凭据而静默退回本地模式。
const DefaultCredentialFileName = cred.FileName

// r2ConfigFile 是 `--r2-config <json>` 的文件结构。
//
// 字段名与 Cloudflare 控制台给出的示例保持一致（下划线风格），
// 这样从控制台复制的凭据片段可以直接存成文件用，不必手工改名。
type r2ConfigFile struct {
	AccountID       string `json:"account_id"`
	Bucket          string `json:"bucket"`
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region"`
	Prefix          string `json:"prefix"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	Label           string `json:"label"`
	Scope           string `json:"scope"`
}

// cmdCred 生成一份受保护的 client.json（F-F01 / F-F02 / F-F905）。
//
// 保护方式三选一，由开关决定（都不给则按平台默认）：
//
//	（默认）        → Windows 上 DPAPI 机器范围；换机器/换系统解不开，Linux 读不了
//	--cred-pass-file / --cred-pass → 口令加密，**跨平台可读**（Linux 解密器要用这种）
//	--plain-file    → 明文，仅 0600 权限保护（最后手段）
//
// 三件事必须讲清楚（F-F910 的提示义务）：
//  1. Secret 不上命令行——它会进 shell 历史与进程命令行（`wmic process` 就能看到）；
//  2. 凭据落在哪台机器就绑定哪台机器（DPAPI 机器范围），拷走解不开；
//  3. token 的权限该给哪一档（见下），以及为什么"只写不读"这一档并不存在。
//
// 关于权限的现实（别按不存在的档位去配）：R2 控制台的长效 token 只有
// Admin Read & Write / Admin Read only / Object Read & Write / Object Read only，
// 可限定到**桶**但不能限定到 **key 前缀**。最小可达权限是
// 「Object Read & Write + 仅限目标桶」，配套桶版本控制 + 定期轮换。
func cmdCred(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cred", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", DefaultCredentialFileName, "输出路径（默认 .\\client.json）")
	fromFile := fs.String("from", "", "从 JSON 文件读取全部字段（--r2-config 的等价写法）")
	accountID := fs.String("account-id", "", "Cloudflare 账户 ID")
	bucket := fs.String("bucket", "", "目标桶名")
	endpoint := fs.String("endpoint", "", "S3 端点（留空则按 account-id 推导）")
	prefix := fs.String("prefix", "", "对象键前缀（默认 usb/）")
	region := fs.String("region", "", "签名区域（R2 固定 auto）")
	akid := fs.String("access-key-id", "", "Access Key ID")
	secret := fs.String("secret-access-key", "", "Secret Access Key（不安全，建议用 --secret-file 或交互输入）")
	secretFile := fs.String("secret-file", "", "从文件读取 Secret Access Key（首行）")
	sessionToken := fs.String("session-token", "", "临时凭据的 Session Token（可选）")
	label := fs.String("label", "", "备注，便于辨认这份凭据属于哪台机器")
	scope := fs.String("scope", string(cred.ScopeUpload), "用途：upload / download / both")
	credPassFile := fs.String("cred-pass-file", "",
		"凭据文件口令（取文件首行）：给出后用口令加密，**跨平台可读**——Linux 解密器读不了 DPAPI 凭据，只能用这种")
	credPassPrompt := fs.Bool("cred-pass", false, "交互式输入凭据文件口令（无回显），等价于 --cred-pass-file")
	plainFile := fs.Bool("plain-file", false,
		"生成**明文**凭据文件（只有 0600 文件权限保护）：无 DPAPI 又没法提供口令时的最后手段")
	force := fs.Bool("force", false, "覆盖已存在的输出文件")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}

	// 哪些 flag 被**显式**给过。只有 scope 需要这个信息：它的默认值恰好也是一个
	// 合法取值（upload），于是"没给"与"显式给了 upload"用 `== ""` 判不出来，
	// 只能问 flag 包。其余字段默认值为空串，用 `== ""` 判"未给"就够。
	scopeSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "scope" {
			scopeSet = true
		}
	})

	c := cred.Credentials{
		AccountID:    strings.TrimSpace(*accountID),
		Bucket:       strings.TrimSpace(*bucket),
		Endpoint:     strings.TrimSpace(*endpoint),
		Region:       strings.TrimSpace(*region),
		Prefix:       strings.TrimSpace(*prefix),
		AccessKeyID:  []byte(strings.TrimSpace(*akid)),
		SessionToken: []byte(strings.TrimSpace(*sessionToken)),
		Label:        strings.TrimSpace(*label),
		Scope:        strings.TrimSpace(*scope),
	}
	var secretBytes []byte
	if s := strings.TrimSpace(*secret); s != "" {
		secretBytes = []byte(s)
		fmt.Fprintln(stderr, "[警告] 通过命令行传入 Secret 会留在 shell 历史与进程命令行里。")
		fmt.Fprintln(stderr, "       建议改用 --secret-file <文件> 或交互式输入。")
	}
	defer func() {
		for i := range secretBytes {
			secretBytes[i] = 0
		}
	}()

	// 1) 从 JSON 文件读（低优先级，后面被命令行覆盖）。
	if p := strings.TrimSpace(*fromFile); p != "" {
		raw, err := os.ReadFile(fsutil.LongPath(p))
		if err != nil {
			fmt.Fprintf(stderr, "错误：读取 R2 配置失败：%v\n", err)
			return cli.ExitRuntime
		}
		var fc r2ConfigFile
		if err := json.Unmarshal(raw, &fc); err != nil {
			fmt.Fprintf(stderr, "错误：解析 R2 配置失败（应为 JSON）：%v\n", err)
			return cli.ExitRuntime
		}
		if c.AccountID == "" {
			c.AccountID = strings.TrimSpace(fc.AccountID)
		}
		if c.Bucket == "" {
			c.Bucket = strings.TrimSpace(fc.Bucket)
		}
		if c.Endpoint == "" {
			c.Endpoint = strings.TrimSpace(fc.Endpoint)
		}
		if c.Region == "" {
			c.Region = strings.TrimSpace(fc.Region)
		}
		if c.Prefix == "" {
			c.Prefix = strings.TrimSpace(fc.Prefix)
		}
		if len(c.AccessKeyID) == 0 {
			c.AccessKeyID = []byte(strings.TrimSpace(fc.AccessKeyID))
		}
		if len(c.SessionToken) == 0 {
			c.SessionToken = []byte(strings.TrimSpace(fc.SessionToken))
		}
		if c.Label == "" {
			c.Label = strings.TrimSpace(fc.Label)
		}
		if !scopeSet && strings.TrimSpace(fc.Scope) != "" {
			c.Scope = strings.TrimSpace(fc.Scope)
		}
		if len(secretBytes) == 0 && strings.TrimSpace(fc.SecretAccessKey) != "" {
			secretBytes = []byte(strings.TrimSpace(fc.SecretAccessKey))
		}
	}

	// 端点越早校验越好：等 Secret 都问完了才报"endpoint 写错了"，
	// 等于让人白输一次敏感信息，还得重来一遍。
	if strings.TrimSpace(c.Endpoint) != "" {
		if err := cred.ValidateEndpoint(c.Endpoint); err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitUsage
		}
	}

	// 2) Secret 的取值顺序：--secret-file > 交互输入。
	if len(secretBytes) == 0 && strings.TrimSpace(*secretFile) != "" {
		p, err := cli.ReadPassphraseFromFile(*secretFile)
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitUsage
		}
		secretBytes = p
	}
	if len(secretBytes) == 0 {
		p, err := cli.ReadPassphrase("请输入 R2 Secret Access Key（无回显）：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		secretBytes = p
	}
	c.SecretAccessKey = secretBytes

	if len(c.AccessKeyID) == 0 {
		id, err := readLine(stdin, stdout, "请输入 R2 Access Key ID：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		c.AccessKeyID = []byte(id)
	}
	if c.AccountID == "" {
		v, err := readLine(stdin, stdout, "请输入 Cloudflare 账户 ID：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		c.AccountID = v
	}
	if c.Bucket == "" {
		v, err := readLine(stdin, stdout, "请输入目标桶名（bucket）：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		c.Bucket = v
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://" + c.AccountID + ".r2.cloudflarestorage.com"
		fmt.Fprintf(stdout, "端点留空，按账户 ID 推导为：%s\n", c.Endpoint)
	}
	if strings.TrimSpace(c.Prefix) == "" {
		c.Prefix = cred.DefaultPrefix
	}
	if strings.TrimSpace(c.Region) == "" {
		c.Region = cred.DefaultRegion
	}
	if strings.TrimSpace(c.Scope) == "" {
		c.Scope = cred.ScopeUpload
	}

	// 3) 凭据文件的保护方式。
	//
	// 不给任何开关时走**平台原生保管设施**：Windows 上是 DPAPI（机器范围），
	// 用起来最省事（不记口令），代价是**只有生成它的那台机器能读**。
	// 因此凡是要把凭据拿到别的机器上用（典型：Linux 解密器要读同一份凭据去拉对象），
	// 就必须显式选一条跨平台的路：
	//
	//	--cred-pass-file / --cred-pass → 口令加密（PBKDF2 + AES-GCM，推荐）
	//	--plain-file                   → 明文（仅靠 0600 权限，最后手段）
	//
	// 不提供"自动降级"：DPAPI 的凭据在 Linux 上读不了这件事必须当场看见，
	// 而不是等到把文件拷到服务器上才发现。
	var credOpts []cred.Option
	var credPass []byte
	passFile := strings.TrimSpace(*credPassFile)
	switch {
	case passFile != "" && *plainFile:
		fmt.Fprintln(stderr, "错误：--cred-pass-file 与 --plain-file 互斥：前者加密、后者不加密。")
		return cli.ExitUsage
	case *credPassPrompt && *plainFile:
		fmt.Fprintln(stderr, "错误：--cred-pass 与 --plain-file 互斥：前者加密、后者不加密。")
		return cli.ExitUsage
	case passFile != "":
		credOpts = append(credOpts, cred.WithPassphraseFile(passFile))
	case *credPassPrompt:
		p, err := cli.ReadPassphrase("请输入凭据文件口令（无回显，至少 8 位）：")
		if err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitRuntime
		}
		credPass = p
		defer func() {
			for i := range credPass {
				credPass[i] = 0
			}
		}()
		credOpts = append(credOpts, cred.WithPassphrase(credPass))
	case *plainFile:
		credOpts = append(credOpts, cred.WithForcePlainFile())
	}

	dest, err := filepath.Abs(*out)
	if err != nil {
		fmt.Fprintf(stderr, "错误：解析输出路径失败：%v\n", err)
		return cli.ExitRuntime
	}
	if _, err := os.Stat(dest); err == nil && !*force {
		fmt.Fprintf(stderr, "错误：%s 已存在（如需覆盖请加 --force）。\n", dest)
		return cli.ExitUsage
	}

	if err := cred.Save(dest, c, credOpts...); err != nil {
		fmt.Fprintf(stderr, "错误：写入凭据失败：%v\n", err)
		return cli.ExitRuntime
	}
	defer c.Zero()

	// 保护方式以**落盘后回读**为准，而不是把刚才的开关翻译一遍：
	// 开关与最终结果一旦不一致（参数冲突、平台不支持），这里就会立刻露出来。
	protection, _ := cred.ProtectionOf(dest)

	fmt.Fprintln(stdout, "\n凭据文件已生成。")
	fmt.Fprintf(stdout, "  文件        : %s\n", dest)
	fmt.Fprintf(stdout, "  保护方式    : %s\n", cred.ProtectionNote(protection))
	fmt.Fprintf(stdout, "  %s\n", strings.ReplaceAll(c.Describe(), "\n", "\n  "))
	fmt.Fprintln(stdout, "\n必须知道的三件事：")
	switch protection {
	case cred.ProtectionPassphrase:
		fmt.Fprintln(stdout, "  1) 凭据用**口令**加密：任何平台都能读，但口令丢了就无解（没有找回途径）。")
		fmt.Fprintf(stdout, "     解密器那边用 `--cred-pass-file %s` 或环境变量 USBBACKUP_R2_CRED_PASSPHRASE 提供，\n",
			passFileNameHint(passFile))
		fmt.Fprintln(stdout, "     口令文件本身放 0600 且**不要**跟凭据放在同一个目录里。")
	case cred.ProtectionPlainFile:
		fmt.Fprintln(stdout, "  1) 凭据是**明文**：只有 0600 文件权限这一层保护，任何拿到该文件的人都能直接用。")
		fmt.Fprintln(stdout, "     只在既没有 DPAPI 又无法在启动时提供口令时使用（例如无 systemd 的极简环境）。")
	default:
		fmt.Fprintln(stdout, "  1) 凭据与**本机**绑定（DPAPI 机器范围）：拷到别的机器/重装系统后解不开。")
		fmt.Fprintln(stdout, "     **Linux 解密器读不了它**——要给 Linux 用，请加 --cred-pass-file 重新生成一份。")
	}
	fmt.Fprintln(stdout, "  2) token 请用「Object Read & Write + 仅限目标桶」，不要用 Admin 两档。")
	fmt.Fprintln(stdout, "     R2 没有「只写不读」这一档，也不能把长效 token 限定到 key 前缀。")
	fmt.Fprintln(stdout, "     因此这一档同时能读/覆盖/删除，必须配套：桶开**版本控制**（覆盖或误删不销毁历史版本）")
	fmt.Fprintln(stdout, "     + **定期轮换** token。要真正做到限前缀只能用临时凭据（TTL ≤ 7 天），不适合常驻客户端。")
	fmt.Fprintf(stdout, "  3) 泄漏时的处置是「吊销 token + 重新生成 %s」——**不需要**重新编译客户端。\n",
		filepath.Base(dest))
	fmt.Fprintln(stdout, "\n下一步：")
	fmt.Fprintf(stdout, "  · 传上去之前先验一下：usbkeygen-r2 r2-check --cred-file %s\n", dest)
	fmt.Fprintf(stdout, "  · 客户端：把它与 client.exe 放在同一个目录，一起部署到目标机器。\n")
	if protection == cred.ProtectionPassphrase {
		fmt.Fprintf(stdout, "  · 解密器：拷一份到 Linux，`usbunseal-r2 config --cred-file %s --cred-pass-file <口令文件路径>`。\n",
			filepath.Base(dest))
	}
	return cli.ExitOK
}

// passFileNameHint 只在真的给了口令文件时回显路径，避免打印一个空字符串。
func passFileNameHint(p string) string {
	if p == "" {
		return "<口令文件路径>"
	}
	return p
}

// cmdR2Check 用给定凭据做一次探活（F-909）。
//
// 检查项刻意串在一起做，因为每一环失败的原因都能从错误里区分出来：
//
//	DNS / 连不上      → 网络或端点写错
//	TLS 失败          → 证书问题（本工具不提供跳过校验的开关）
//	403 SignatureDoesNotMatch → 时钟偏移或 Secret 抄错
//	403 AccessDenied  → token 权限不对（或前缀不在允许范围内）
//	其余 2xx/4xx 组合 → 按错误码逐条报
//
// 探活对象放在配置的前缀下、写完立刻删除；不会留下垃圾。
func cmdR2Check(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("r2-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	credFile := fs.String("cred-file", "", "凭据文件路径（默认 .\\client.json）")
	credPassFile := fs.String("cred-pass-file", "", "凭据文件口令（首行）；凭据是口令加密时必须给")
	allowPlainCred := fs.Bool("allow-plain-cred", false, "允许读取未加密的凭据文件（仅 --plain-file 产出的那种）")
	timeoutMin := fs.Int("timeout", 2, "单次请求总超时（分钟）")
	keepProbe := fs.Bool("keep-probe", false, "保留探活对象（默认写完立刻删除）")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}

	path := strings.TrimSpace(*credFile)
	if path == "" {
		path = DefaultCredentialFileName
	}
	path = config.ExpandPath(path)

	protection, protErr := cred.ProtectionOf(path)
	if protErr != nil {
		fmt.Fprintf(stderr, "错误：%v\n", protErr)
		fmt.Fprintln(stderr, "提示：先用 `usbkeygen-r2 cred` 生成一份，或用 --cred-file 指定路径。")
		return cli.ExitRuntime
	}

	var loadOpts []cred.Option
	switch protection {
	case cred.ProtectionPassphrase:
		if p := strings.TrimSpace(*credPassFile); p != "" {
			loadOpts = append(loadOpts, cred.WithPassphraseFile(p))
		} else {
			// 现场问一次，比让人对着 ErrPassphraseRequired 猜要强。
			pass, perr := cli.ReadPassphrase("凭据文件已加密，请输入口令（无回显）：")
			if perr != nil {
				fmt.Fprintf(stderr, "错误：%v\n", perr)
				return cli.ExitRuntime
			}
			defer func() {
				for i := range pass {
					pass[i] = 0
				}
			}()
			loadOpts = append(loadOpts, cred.WithPassphrase(pass))
		}
	case cred.ProtectionPlainFile:
		if !*allowPlainCred {
			fmt.Fprintf(stderr, "错误：凭据文件是明文（%s），需显式加 --allow-plain-cred 才读。\n", path)
			fmt.Fprintln(stderr, "提示：明文凭据等于把 token 摊开，请确认这是你有意为之；"+
				"更稳妥的是用 `usbkeygen-r2 cred --cred-pass-file <口令文件> --force` 重新生成一份口令加密的。")
			return cli.ExitUsage
		}
		loadOpts = append(loadOpts, cred.WithAllowPlainFile())
	}

	c, err := cred.Load(path, loadOpts...)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		fmt.Fprintln(stderr, "提示：先用 `usbkeygen-r2 cred` 生成一份，或用 --cred-file 指定路径。")
		return cli.ExitRuntime
	}
	defer c.Zero()

	fmt.Fprintf(stdout, "凭据文件  : %s\n", path)
	fmt.Fprintf(stdout, "保护方式  : %s\n", cred.ProtectionNote(protection))
	fmt.Fprintf(stdout, "  %s\n\n", strings.ReplaceAll(c.Describe(), "\n", "\n  "))

	client, err := r2.New(r2.Options{
		Endpoint:        c.Endpoint,
		Bucket:          c.Bucket,
		Region:          c.EffectiveRegion(),
		AccessKeyID:     string(c.AccessKeyID),
		SecretAccessKey: string(c.SecretAccessKey),
		SessionToken:    string(c.SessionToken),
		MaxRetries:      1,
		UserAgent:       version.AppName + "/" + version.Version,
	})
	if err != nil {
		fmt.Fprintf(stderr, "错误：无法构造客户端：%v\n", err)
		return cli.ExitRuntime
	}

	ctx := context.Background()
	if *timeoutMin > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*timeoutMin)*time.Minute)
		defer cancel()
	}

	problems := 0
	report := func(name string, ok bool, detail string) {
		mark := "OK  "
		if !ok {
			mark = "FAIL"
			problems++
		}
		fmt.Fprintf(stdout, "  [%s] %s %s\n", mark, name, detail)
	}
	// warn 是"不算失败、但需要你看一眼"的结论（例如权限开大了）。
	warn := func(name, detail string) {
		fmt.Fprintf(stdout, "  [WARN] %s %s\n", name, detail)
	}

	// 单次 PUT 探活对象 → HEAD 核对 → 删除。
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	key := cred.NormalizePrefix(c.EffectivePrefix()) + "probe-" + hex.EncodeToString(suffix) + ".txt"
	body := []byte("usbbackup-r2 r2-check probe\n" + time.Now().Format(time.RFC3339) + "\n")

	fmt.Fprintln(stdout, "检查项：")
	info, perr := client.PutObject(ctx, key, bytes.NewReader(body), int64(len(body)), nil)
	if perr != nil {
		report("写入对象（Object Write）", false, explainR2Error(perr))
		fmt.Fprintf(stdout, "\n探活对象未写入成功，后续检查跳过。\n")
		return cli.ExitPartial
	}
	report("写入对象（Object Write）", true, fmt.Sprintf("已写入 %s（ETag %s）", key, info.ETag))

	head, herr := client.Head(ctx, key)
	if herr != nil {
		report("读回对象元数据（HeadObject）", false, explainR2Error(herr))
	} else if head.Size != int64(len(body)) {
		report("读回对象元数据（HeadObject）", false,
			fmt.Sprintf("远端大小 %d，本地 %d（可能被中间层改写？）", head.Size, len(body)))
	} else {
		report("读回对象元数据（HeadObject）", true, fmt.Sprintf("大小 %d 字节一致", head.Size))
	}

	// 权限过大检测：见 r2.Client.ListBuckets 的说明。
	//
	// R2 控制台的长效 token 只有四档权限，其中能列举桶的只有 Admin 两档。
	// 所以**列举成功就是越权**，列举被拒（403）才是期望结果——这一步不算失败项，
	// 它只是把"token 权限开大了"这件事摆到台面上，让人有机会收紧。
	if names, lerr := client.ListBuckets(ctx); lerr == nil {
		warn("权限范围（ListBuckets）", fmt.Sprintf(
			"该 token 能列举账户下的桶（可见 %d 个），说明它是 Admin 级权限，远超上传备份所需；"+
				"请换成「Object Read & Write + 仅限目标桶」这一档", len(names)))
	} else if r2.IsForbidden(lerr) {
		report("权限范围（ListBuckets）", true, "已被拒绝，说明不是账户级 Admin 权限")
	} else {
		warn("权限范围（ListBuckets）", "无法判定（"+explainR2Error(lerr)+"）")
	}

	if *keepProbe {
		fmt.Fprintf(stdout, "\n已按 --keep-probe 保留探活对象：%s\n", key)
		fmt.Fprintln(stdout, "记得事后自行删除，否则会在桶里留下垃圾。")
	} else if derr := client.Delete(ctx, key); derr != nil {
		report("清理探活对象", false, explainR2Error(derr))
		fmt.Fprintf(stdout, "  请手工删除：%s\n", key)
	} else {
		report("清理探活对象", true, "已删除（不留垃圾）")
	}

	if problems > 0 {
		fmt.Fprintf(stderr, "\n共 %d 项检查未通过。\n", problems)
		return cli.ExitPartial
	}
	fmt.Fprintln(stdout, "\n全部检查通过：端点可达、签名被接受、该前缀下可写。")
	return cli.ExitOK
}

// explainR2Error 把一次探活失败翻译成可执行的排查方向。
//
// 这一步值得单独写：403 的两种成因（签名错 / 权限不足）排查方法完全不同，
// 只回一句 "AccessDenied" 会让人先去折腾权限，而真正的问题是时钟偏移。
func explainR2Error(err error) string {
	msg := err.Error()
	switch {
	case r2.IsForbidden(err):
		if strings.Contains(msg, "SignatureDoesNotMatch") {
			return "签名被拒：请核对 Secret Access Key，并确认本机时间与标准时间一致（SigV4 对时钟敏感）：" + msg
		}
		return "权限不足：token 的权限范围没覆盖目标桶（应为「Object Read & Write + 仅限该桶」）：" + msg
	case r2.IsNotFound(err):
		return "桶或对象不存在：请核对 bucket 名与 endpoint 的账户 ID：" + msg
	case strings.Contains(msg, "x509") || strings.Contains(msg, "certificate"):
		return "TLS 证书校验失败（本工具不提供跳过校验的开关）：" + msg
	case strings.Contains(msg, "no such host") || strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "connection refused") || strings.Contains(msg, "timeout"):
		return "连不上端点：检查网络、代理与 endpoint 写法：" + msg
	default:
		return msg
	}
}

// readLine 从 stdin 读一行非敏感输入。
func readLine(stdin io.Reader, stdout io.Writer, prompt string) (string, error) {
	fmt.Fprint(stdout, prompt)
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			if buf[0] != '\r' {
				b.WriteByte(buf[0])
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
	}
	v := strings.TrimSpace(b.String())
	if v == "" {
		return "", fmt.Errorf("输入为空")
	}
	return v, nil
}
