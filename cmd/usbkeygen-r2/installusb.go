package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/immml/UsbBackUP-R2/internal/cli"
	"github.com/immml/UsbBackUP-R2/internal/clientgen"
	"github.com/immml/UsbBackUP-R2/internal/collectpolicy"
	"github.com/immml/UsbBackUP-R2/internal/cred"
	"github.com/immml/UsbBackUP-R2/internal/keystore"
	"github.com/immml/UsbBackUP-R2/internal/version"
	"github.com/immml/UsbBackUP-R2/internal/winvol"
)

// toolFiles 是要装进工具 U 盘的可执行文件（相对本程序所在目录）。
var toolFiles = []string{
	"usbsetup-r2.exe", "usbkeygen-r2.exe", "usbunseal-r2.exe", "usbbackup-r2.exe", "usbcomp-r2.exe",
}

// toolkitOptions 是组装工具盘的输入。
type toolkitOptions struct {
	// Dest 是目标根目录（U 盘根目录）。
	Dest string
	// SubDir 是工具在盘内的相对子目录（如 `backup\tools`）；空表示直接放盘根。
	//
	// 注意：两个授权标记（`.usbbackup-allow` / `.usbbackup-allow-disk`）
	// 不受它影响，永远写在 Dest 下——标记只在**卷根**被检查
	// （collectpolicy 只 Stat `<root>\.usbbackup-allow`），
	// 一旦挪进子目录，这个盘就会被当成普通介质采集走。
	SubDir string
	// ToolDir 是工具 exe 的来源目录（一般是本程序所在目录）。
	ToolDir string
	// PublicKeyPath / PrivateKeyPath 是密钥来源。
	PublicKeyPath  string
	PrivateKeyPath string
	// WithPrivate 决定是否把私钥写进 U 盘。
	WithPrivate bool
	// WithClient 决定是否生成/复制 client.exe。
	WithClient bool
	// CredentialPath 是可选的 R2 凭据文件，给了就一并放进盘里并让客户端带上上传能力。
	CredentialPath string

	// Upload 显式要求内嵌客户端开启上传能力，**但不在盘上放凭据**。
	//
	// 这是工具盘的常规形态：盘只当分发介质，凭据在目标机器上现场生成
	// （DPAPI 机器绑定档，之后零环境变量）。若把上传能力与"带凭据"绑死，
	// 这种形态产出的 client.exe 会静默关着上传——而 README 写着"会自动上传到 R2"，
	// 现场表现就是"跑了半天，R2 上什么都没有"，且不报错。
	//
	// 与 CredentialPath 同时给出不冲突（带凭据本就意味着要上传）。
	Upload bool

	// NoUpload 显式关闭上传能力。与 Upload 互斥。
	//
	// 三者都不给时的默认是"有凭据就开、没凭据就关"——保持既有行为不变，
	// 免得改了默认值把别人已有的脚本产出反过来。
	NoUpload bool

	// CredTemplatePath 是随盘分发的**凭据素材**（写进盘里叫 r2.json）。
	//
	// 它只有路由信息、secret 留空，供目标机器现场生成机器绑定的凭据。
	// 与 CredentialPath（真正的 client.json）互不相同，也别混用：
	// 前者是"生成凭据的输入"，后者是"能直接用的凭据"。
	CredTemplatePath string

	// Threshold / MaxTotal / Collect 覆盖内嵌客户端里的容量门控与采集策略。
	//
	// 这三个必须在这里可注入：装盘产出的 client.exe 是要直接拷到目标机器上跑的，
	// 若只能用内置默认值，就没办法为现场调整门控——而默认阈值（10 GiB）
	// 对大容量介质、或者反过来"我只想备小盘"的场景都不一定合适。
	// 空串表示沿用内置默认配置。
	Threshold string
	MaxTotal  string
	Collect   string

	// Force 允许覆盖已存在的同名文件。
	Force bool
}

// cmdInstallUSB 把一个「便携工具 U 盘」组装到指定盘符。
//
// 盘内布局：
//
//	<U盘>\
//	├── usbsetup-r2.exe / usbkeygen-r2.exe / usbunseal-r2.exe / usbbackup-r2.exe / usbcomp-r2.exe
//	├── client.exe            生成器产出的客户端（内嵌配置与公钥）
//	├── client.json           可选：R2 凭据（DPAPI 保护，与 client.exe 同目录）
//	├── r2.json               可选：凭据素材（**不含 secret**），供目标机器现场生成凭据
//	├── keys\usbbackup-r2.pub.pem
//	├── keys\usbbackup-r2.key.pem（默认带；--without-private 可排除）
//	├── .usbbackup-allow     授权标记（卷级）：本卷豁免
//	├── .usbbackup-allow-disk 授权标记（磁盘级）：同一物理磁盘上所有卷一起豁免
//	└── README.txt            用法与私钥风险说明
//
// 上传能力与"带不带凭据"是**两件事**：--upload 让内嵌客户端开启上传但盘上不放凭据
// （凭据在目标机器上现场生成，DPAPI 机器绑定档），--cred 则是凭据 + 上传一起进盘。
// 只有在这两个都不给时才关闭上传。
//
// 两个授权标记的语义都是**豁免**：客户端读到卷级那份就知道"这是自己人的卷，
// 里面甚至有私钥"，于是拒绝采集；读到磁盘级那份则把范围放大到**整块物理磁盘**
// ——多分区介质（Ventoy 盘是最典型的）必须靠后者，否则只在主分区放标记时，
// 固件分区会被当成陌生介质整盘打包上传。
//
// `.usbbackup-allow` 这个文件名与不含出站能力的版本（项目 A）完全一致，两边的盘互相认；
// `.usbbackup-allow-disk` 是本项目新增的，A 不认它，但也不受影响（A 只看前者）。
func cmdInstallUSB(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install-usb", flag.ContinueOnError)
	fs.SetOutput(stderr)
	drive := fs.String("drive", "", "目标 U 盘盘符，如 E:（必填）")
	subDir := fs.String("subdir", "", "工具在盘内的子目录，如 backup\\tools（默认放盘根）")
	pub := fs.String("public", "", "公钥路径（默认与本程序同目录的 keys/usbbackup-r2.pub.pem）")
	priv := fs.String("private", "", "私钥路径（默认与本程序同目录的 keys/usbbackup-r2.key.pem）")
	keyDir := fs.String("keys", "", "密钥目录（同时给出公钥与私钥时可只写这一项）")
	credPath := fs.String("cred", "", "一并放进盘内的 R2 凭据 client.json（可选，给了则客户端带上传能力）")
	upload := fs.Bool("upload", false, "内嵌客户端开启上传能力，但**不**在盘上放凭据（目标机器现场生成）")
	noUpload := fs.Bool("no-upload", false, "内嵌客户端关闭上传能力（产物只落本地）")
	credTemplate := fs.String("cred-template", "", "随盘分发的凭据素材（写进盘里叫 r2.json；其中 secret 字段必须为空）")
	threshold := fs.String("threshold", "", "内嵌客户端的容量门控阈值（如 10GiB；空则用内置默认）")
	maxTotal := fs.String("max-total", "", "内嵌客户端的打包体积上限（如 10GiB；0 / unlimited 表示不限制）")
	collect := fs.String("collect", "", "内嵌客户端的采集策略：all / marker_only / off")
	withoutPriv := fs.Bool("without-private", false, "不把私钥写进 U 盘")
	noClient := fs.Bool("no-client", false, "不生成/复制 client.exe")
	force := fs.Bool("force", false, "目标已有同名文件时覆盖")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if strings.TrimSpace(*drive) == "" {
		fmt.Fprintln(stderr, "用法：usbkeygen-r2 install-usb --drive E: [--keys DIR] [--subdir backup\\tools]")
		fmt.Fprintln(stderr, "      [--cred client.json] [--upload | --no-upload] [--cred-template r2.json]")
		fmt.Fprintln(stderr, "      [--threshold 10GiB] [--max-total 10GiB] [--collect all]")
		fmt.Fprintln(stderr, "      [--without-private] [--no-client] [--force]")
		return cli.ExitUsage
	}
	// 两个上传开关互斥：同时给出说明调用方自己也没想清要哪一种，
	// 硬选一个就会产出与预期相反的盘。
	if *upload && *noUpload {
		fmt.Fprintln(stderr, "错误：--upload 与 --no-upload 不能同时给出。")
		return cli.ExitUsage
	}
	// --cred 本身就意味着"要上传"（凭据 + 上传能力一起进盘）。再叠一个
	// --no-upload 会产出一块"带凭据却不会上传"的盘，没有任何场景需要它。
	if *noUpload && strings.TrimSpace(*credPath) != "" {
		fmt.Fprintln(stderr, "错误：--no-upload 与 --cred 冲突——带凭据进盘就是要用它的上传能力。")
		fmt.Fprintln(stderr, "      只想要凭据、不要上传：别给 --cred，改成先把凭据单独分发。")
		return cli.ExitUsage
	}
	// 采集策略先校验再动手：写坏一块盘要全部重来，而这些值在动手前就能判断对错。
	// 非法取值必须当场报错，不能静默退回默认——那会让人以为生效了。
	if strings.TrimSpace(*collect) != "" {
		if _, err := collectpolicy.Normalize(*collect); err != nil {
			fmt.Fprintf(stderr, "错误：%v\n", err)
			return cli.ExitUsage
		}
	}
	// 先规范化再校验：非法值（绝对路径 / 含 ..）直接按"不指定"处理会让人以为生效了，
	// 所以这里明确报错，而不是静默退化。
	sub := cleanSubDir(*subDir)
	if strings.TrimSpace(*subDir) != "" && sub == "" {
		fmt.Fprintf(stderr, "错误：--subdir %q 不是合法的相对子目录（不接受绝对路径、盘符或 ..）。\n", *subDir)
		return cli.ExitUsage
	}

	root, err := winvol.NormalizeRoot(*drive)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitUsage
	}
	vol, err := winvol.Query(root)
	if err != nil {
		// 区分"盘符不存在/没插介质"与"插了但不是 U 盘"：
		// 两者的处理办法完全不同，报成同一句会让人白找半天。
		if vol.DriveType == winvol.DriveNoRootDir || vol.DriveType == winvol.DriveUnknown {
			fmt.Fprintf(stderr, "错误：%s 不存在或没有插入介质。\n", root)
			return cli.ExitRuntime
		}
		fmt.Fprintf(stderr, "错误：无法访问 %s：%v\n", root, err)
		return cli.ExitRuntime
	}
	if !vol.Ready {
		fmt.Fprintf(stderr, "错误：%s 未就绪（介质未插入？）\n", root)
		return cli.ExitRuntime
	}
	if !vol.Removable {
		fmt.Fprintf(stderr, "错误：%s 不是可移动磁盘（类型 %s），拒绝写入。\n", root, winvol.DriveTypeName(vol.DriveType))
		fmt.Fprintln(stderr, "      这个命令只往 U 盘装东西；若是固定盘请确认盘符。")
		return cli.ExitUsage
	}

	exeDir := exeDirOf()
	pubPath := firstNonEmpty(*pub, filepath.Join(*keyDir, "usbbackup-r2.pub.pem"), filepath.Join(exeDir, "keys", "usbbackup-r2.pub.pem"))
	privPath := firstNonEmpty(*priv, filepath.Join(*keyDir, "usbbackup-r2.key.pem"), filepath.Join(exeDir, "keys", "usbbackup-r2.key.pem"))

	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误：读取公钥失败：%v\n", err)
		fmt.Fprintln(stderr, "      请用 --public 指定，或先执行 usbkeygen-r2 generate。")
		return cli.ExitRuntime
	}
	pubKey, err := keystore.ParsePublicKeyPEM(pubRaw)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}
	_, fpText, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		fmt.Fprintf(stderr, "错误：计算公钥指纹失败：%v\n", err)
		return cli.ExitRuntime
	}

	withPriv := !*withoutPriv
	if withPriv {
		if _, err := os.Stat(privPath); err != nil {
			fmt.Fprintf(stderr, "提示：未找到私钥 %s，本次不写入私钥。\n", privPath)
			withPriv = false
		}
	}

	fmt.Fprintf(stdout, "目标 U 盘  : %s（%s，剩余 %s）\n", root, emptyOr(vol.Label, "无卷标"), humanBytes(vol.FreeBytes))
	if sub != "" {
		fmt.Fprintf(stdout, "工具目录  : %s（授权标记仍写盘根）\n", filepath.Join(root, sub))
	}
	fmt.Fprintf(stdout, "公钥指纹  : %s\n", fpText)
	fmt.Fprintf(stdout, "写入私钥  : %v\n\n", withPriv)

	n, err := assembleToolkit(toolkitOptions{
		Dest:             root,
		SubDir:           sub,
		ToolDir:          exeDir,
		PublicKeyPath:    pubPath,
		PrivateKeyPath:   privPath,
		WithPrivate:      withPriv,
		WithClient:       !*noClient,
		CredentialPath:   strings.TrimSpace(*credPath),
		Upload:           *upload,
		NoUpload:         *noUpload,
		CredTemplatePath: strings.TrimSpace(*credTemplate),
		Threshold:        strings.TrimSpace(*threshold),
		MaxTotal:         strings.TrimSpace(*maxTotal),
		Collect:          strings.TrimSpace(*collect),
		Force:            *force,
	}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "错误：%v\n", err)
		return cli.ExitRuntime
	}

	fmt.Fprintf(stdout, "\n完成：共写入 %d 项到 %s\n", n, root)
	if withPriv {
		fmt.Fprintln(stdout)
		if privateIsEncrypted(toolkitOptions{WithPrivate: true, PrivateKeyPath: privPath}) {
			fmt.Fprintln(stdout, "  [!] 盘上有**带口令的私钥**。盘与口令同时丢失 = 所有备份可被解开，")
			fmt.Fprintln(stdout, "      且口令不要写在这个盘上。请随身保管，或改用 --without-private 只带公钥。")
		} else {
			fmt.Fprintln(stdout, "  [!] 盘上有**明文私钥**。U 盘一旦丢失或被复制，")
			fmt.Fprintln(stdout, "      所有用它加密的备份都能被解开。请随身保管，")
			fmt.Fprintln(stdout, "      或改用 --without-private 只带公钥。")
		}
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  这个盘不会再被客户端采集走：盘根写了两个授权标记——")
	fmt.Fprintln(stdout, "    .usbbackup-allow       → 本卷豁免（与另一版本共用，它的客户端也认）")
	fmt.Fprintln(stdout, "    .usbbackup-allow-disk  → 同一物理磁盘上**所有卷**一起豁免")
	fmt.Fprintln(stdout, "  第二个是必需的：多分区盘（Ventoy 之类）只在主分区放标记时，")
	fmt.Fprintln(stdout, "  其余分区会被当成陌生介质整盘打包上传。")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  用法：把 %s 所在目录整个拷到目标机的本地目录（**别直接在盘上跑**——\n",
		pathOnDisk(root, sub, "client.exe"))
	fmt.Fprintln(stdout, "        install-service 会把服务绑死在盘符上，拔盘即失效）；")
	fmt.Fprintln(stdout, "        在本地目录里先 client.exe accept 一次，之后 client.exe run 静默常驻；")
	if strings.TrimSpace(*credPath) != "" {
		fmt.Fprintln(stdout, "        客户端会按盘内 client.json 把加密产物自动上传到 R2。")
		// 按凭据**实际**的保护方式给部署提示。写死成 DPAPI 会让拿着口令凭据的人
		// 以为"必须换机重生成"，白跑一趟；反过来则更糟。
		switch credentialProtection(*credPath) {
		case cred.ProtectionDPAPIMachine:
			fmt.Fprintln(stdout, "        [!] 这份凭据是 DPAPI 机器绑定的：本盘上的它**只在生成它的那台机器上**有效，")
			fmt.Fprintln(stdout, "            换机器要重新生成一份（r2perm.py build + shield，或 usbkeygen-r2 cred）。")
		case cred.ProtectionPassphrase:
			fmt.Fprintln(stdout, "        这份凭据是口令加密的，**任何 Windows 机器都能用**——")
			fmt.Fprintln(stdout, "        但客户端只认两个环境变量（它没有 --cred-pass-file 开关）：")
			fmt.Fprintln(stdout, "          USBBACKUP_R2_CRED_PASSPHRASE_FILE / USBBACKUP_R2_CRED_PASSPHRASE")
			fmt.Fprintln(stdout, "        漏设不会报错，只是上传被跳过、产物只留本地——请照盘上 README 第 0 步做。")
			fmt.Fprintln(stdout, "        口令**没有写在盘上**（按设计），请另行保管。")
		case cred.ProtectionPlainFile:
			fmt.Fprintln(stdout, "        [!] 这份凭据是**明文**的，读到盘就拿到了 R2 访问权。")
			fmt.Fprintln(stdout, "            客户端**无人值守时会自动放行读取**（服务没有控制台可交互），")
			fmt.Fprintln(stdout, "            所以现场不会有「读取被拒」这种提示——只有日志里一条 WARN。")
			fmt.Fprintln(stdout, "            交互式命令（usbunseal-r2 / r2-check）仍要求显式 --allow-plain-cred。")
		default:
			fmt.Fprintln(stdout, "        [!] 这份凭据的保护方式未能识别，部署前请自行确认。")
		}
	} else if *upload {
		fmt.Fprintln(stdout, "        上传能力已开，盘上不放明文凭据：到目标机跑 install\\install.cmd，")
		fmt.Fprintln(stdout, "        它用 install\\client.bin + .machine.key **解开凭据，全程不问任何密钥**。")
		fmt.Fprintln(stdout, "        （那一步是可再生的：重生成 client.bin 就换一把；见 README.txt。）")
		fmt.Fprintln(stdout, "        详见盘内 README.txt 的「关于 R2 凭据」一节。")
	}
	fmt.Fprintf(stdout, "        取回 .usbk 后，用 usbunseal-r2.exe 解密还原：\n")
	fmt.Fprintln(stdout, "          usbunseal-r2.exe pull --out <目录> --key keys\\usbbackup-r2.key.pem")
	return cli.ExitOK
}

// assembleToolkit 把工具、客户端、密钥、授权标记与说明写入目标根目录。
//
// 与盘符校验分离，这样即使机器上没有可移动介质，
// 这段组装逻辑也能在临时目录里被单元测试覆盖。
func assembleToolkit(opt toolkitOptions, out io.Writer) (int, error) {
	written := 0

	base, err := toolkitBaseDir(opt)
	if err != nil {
		return written, err
	}

	// 1) 工具本体：缺失的跳过（允许只带部分工具）。
	for _, name := range toolFiles {
		src := filepath.Join(opt.ToolDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyFile(src, filepath.Join(base, name), opt.Force); err != nil {
			return written, fmt.Errorf("复制 %s 失败: %w", name, err)
		}
		written++
		fmt.Fprintf(out, "  [OK] %s\n", relOnDisk(opt, name))
	}

	// 2) 客户端：优先复用同目录已有的，否则现场生成一个。
	//
	// gateXxx 记录**实际写进二进制**的门控值，交给第 5 步的 README 如实写下来。
	// 装盘之后无从反查内嵌块，说明文件里含糊就等于没有。
	var gateThreshold, gateMaxTotal, gateCollect string
	gateUpload := false
	gateFromExisting := false
	if opt.WithClient {
		dst := filepath.Join(base, "client.exe")
		clientSrc := filepath.Join(opt.ToolDir, "client.exe")
		if _, err := os.Stat(clientSrc); err == nil {
			// 复用已有的 client.exe 时，--threshold / --max-total / --collect / --upload
			// 全都无处可施：内嵌块已经定死在那个二进制里了。这种情况必须报错而不是忽略——
			// 忽略的后果是"你以为开关改了，盘上跑的其实还是旧的"，
			// 而这种偏差要等到整盘被跳过、上传撞上体积上限、或者干脆什么都没上传
			// 的时候才会暴露出来。
			if opt.Threshold != "" || opt.MaxTotal != "" || opt.Collect != "" ||
				opt.Upload || opt.NoUpload {
				return written, fmt.Errorf(
					"同目录已存在 %s，无法套用 --threshold / --max-total / --collect / --upload（内嵌配置已定死）\n"+
						"      要么去掉这几个开关，改用它的内嵌值；要么先把那份 client.exe 移走，\n"+
						"      让本命令现场重新生成一个再装盘", clientSrc)
			}
			if err := copyFile(clientSrc, dst, opt.Force); err != nil {
				return written, fmt.Errorf("复制 client.exe 失败: %w", err)
			}
			gateFromExisting = true
			fmt.Fprintf(out, "  [OK] %s（复用已有）\n", relOnDisk(opt, "client.exe"))
		} else {
			pubRaw, err := os.ReadFile(opt.PublicKeyPath)
			if err != nil {
				return written, fmt.Errorf("读取公钥失败: %w", err)
			}
			// 内嵌的凭据名用相对名，客户端按"与自身同目录"解析。
			build := clientgen.Options{
				PublicKeyPEM: pubRaw,
				Template:     filepath.Join(opt.ToolDir, "usbbackup-r2.exe"),
				Output:       dst,
				ClientName:   "usb-toolkit",
				Threshold:    opt.Threshold,
				MaxTotal:     opt.MaxTotal,
				Collect:      opt.Collect,
				Force:        opt.Force,
			}
			// 上传能力的三种来源，优先级从高到低：显式 --no-upload、
			// 显式 --upload、以及"给了凭据就开"的旧默认。
			//
			// 必须把 --upload 单独拎出来：工具盘的常规形态是**不带凭据**、
			// 由目标机器现场生成 DPAPI 凭据。若只按"有没有凭据"决定，
			// 这种盘产出的 client.exe 会静默关着上传，而盘内 README 却写着
			// "会自动上传到 R2"——现场表现是"跑了半天，R2 上什么都没有"。
			switch {
			case opt.NoUpload:
				build.EnableUpload = false
			case opt.Upload:
				build.EnableUpload = true
			default:
				build.EnableUpload = opt.CredentialPath != ""
			}
			if opt.CredentialPath != "" {
				// 内嵌的凭据名用相对名，客户端按"与自身同目录"解析。
				build.CredentialFile = DefaultCredentialFileName
			}
			res, err := clientgen.Build(build)
			if err != nil {
				return written, fmt.Errorf("生成 client.exe 失败: %w", err)
			}
			fmt.Fprintf(out, "  [OK] %s（现场生成，%d 位公钥，上传 %v）\n",
				relOnDisk(opt, "client.exe"), res.KeyBits, res.UploadEnabled)
			gateThreshold, gateMaxTotal = res.ThresholdText, res.MaxTotalText
			gateUpload = res.UploadEnabled
			if res.Config != nil {
				gateCollect = res.Config.Collect.Policy
			}
			fmt.Fprintf(out, "       容量门控：已占用 ≤ %s，打包体积 ≤ %s；采集策略 %s\n",
				emptyOr(gateThreshold, "默认"), emptyOr(gateMaxTotal, "不限制"), emptyOr(gateCollect, "默认"))
		}
		written++
	}

	// 2b) R2 凭据（可选）。
	//
	// 这里**不能把保护方式写死**。凭据现在有三种保护方式，装盘的效果完全不同：
	// DPAPI 那份换机就解不开（盘上带着它只是"便于当场重生成"），
	// 口令保护的那份则任何 Windows 机器都能用。写死成 DPAPI 会让拿着
	// 口令凭据的人白跑一趟，反过来更糟——以为换机就能用。
	if opt.CredentialPath != "" {
		if _, err := os.Stat(opt.CredentialPath); err != nil {
			return written, fmt.Errorf("读取 R2 凭据失败: %w", err)
		}
		if err := copyFile(opt.CredentialPath, filepath.Join(base, DefaultCredentialFileName), opt.Force); err != nil {
			return written, fmt.Errorf("写入 %s 失败: %w", DefaultCredentialFileName, err)
		}
		fmt.Fprintf(out, "  [OK] %s（%s）\n",
			relOnDisk(opt, DefaultCredentialFileName), protectionShort(credentialProtection(opt.CredentialPath)))
		written++
	}

	// 2c) 凭据素材 r2.json：**不含 secret**，供目标机器现场生成 client.json。
	//
	// 工具盘的常规形态是"上传能力开着、盘上却刻意不带凭据"（见 --upload）。
	// 那种形态下目标机器必须自己生成一份机器绑定的凭据，而生成需要账号/桶/端点
	// 这些路由信息——没有这份素材，现场只能靠手抄。
	if opt.CredTemplatePath != "" {
		if err := checkCredentialTemplateHasNoSecret(opt.CredTemplatePath); err != nil {
			return written, err
		}
		if err := copyFile(opt.CredTemplatePath, filepath.Join(base, CredentialTemplateFileName), opt.Force); err != nil {
			return written, fmt.Errorf("写入 %s 失败: %w", CredentialTemplateFileName, err)
		}
		fmt.Fprintf(out, "  [OK] %s（凭据素材，已确认不含 secret）\n", relOnDisk(opt, CredentialTemplateFileName))
		written++
	}

	// 3) 密钥目录。
	keyDst := filepath.Join(base, "keys")
	if err := os.MkdirAll(keyDst, 0o755); err != nil {
		return written, fmt.Errorf("创建 keys 目录失败: %w", err)
	}
	if err := copyFile(opt.PublicKeyPath, filepath.Join(keyDst, "usbbackup-r2.pub.pem"), opt.Force); err != nil {
		return written, fmt.Errorf("写入公钥失败: %w", err)
	}
	fmt.Fprintf(out, "  [OK] %s\n", relOnDisk(opt, filepath.Join("keys", "usbbackup-r2.pub.pem")))
	written++
	if opt.WithPrivate {
		if err := copyFile(opt.PrivateKeyPath, filepath.Join(keyDst, "usbbackup-r2.key.pem"), opt.Force); err != nil {
			return written, fmt.Errorf("写入私钥失败: %w", err)
		}
		kind := "明文"
		if raw, err := os.ReadFile(opt.PrivateKeyPath); err == nil && keystore.IsEncryptedPrivateKeyPEM(raw) {
			kind = "口令保护"
		}
		fmt.Fprintf(out, "  [OK] %s（%s）\n",
			relOnDisk(opt, filepath.Join("keys", "usbbackup-r2.key.pem")), kind)
		written++
	}

	// 4) 授权标记：让客户端**拒绝采集**这个盘。
	//
	// 名字与不含出站能力的版本（项目 A）保持一致：两边的工具盘互相认。
	// 内容写公钥指纹，便于人肉核对"这块盘是谁的"；本项目的判定只看**存在性**
	// （能往盘根写文件的人本来就能伪造内容，靠内容做权限判定是假的）。
	//
	// 但**写入方式必须是追加，不能覆盖**：项目 A 的判定是逐行比对指纹
	// （keyfile.MatchAllowMarker），而同一个盘根完全可能已经躺着 A 写的指纹
	// ——本项目自己的工具盘就是这种情况。整体覆盖会让 A 认不出这块盘，
	// 于是 A 把它当成普通介质扫描打包，而这块盘里有私钥。
	// 一次"顺手覆盖"就能造成私钥外泄，所以这里只追加。
	pubRaw, err := os.ReadFile(opt.PublicKeyPath)
	if err != nil {
		return written, err
	}
	pubKey, err := keystore.ParsePublicKeyPEM(pubRaw)
	if err != nil {
		return written, err
	}
	_, fpText, err := keystore.PublicKeyFingerprint(pubKey)
	if err != nil {
		return written, err
	}
	action, err := mergeExemptMarker(filepath.Join(opt.Dest, ".usbbackup-allow"), fpText)
	if err != nil {
		return written, fmt.Errorf("写入授权标记失败: %w", err)
	}
	fmt.Fprintf(out, "  [OK] .usbbackup-allow（授权标记 → 本盘被豁免；%s）\n", action)
	written++

	// 4b) 磁盘级授权标记：把豁免的作用域从**这个卷**提升到**整块物理磁盘**。
	//
	// 为什么必须多写这一个：卷级标记只认写了它的那个卷根，而使用者的心智模型是
	// "这支 U 盘"。一支 Ventoy 盘必然有第二个分区（VTOYEFI），只在数据区放标记时，
	// 客户端扫到那个分区照样整盘打包上传——2026-09-20 部署实测就是这么踩到的
	// （27.44 MiB 的固件分区被采集）。
	//
	// 只写主分区的盘根即可：判定时会去查同一物理磁盘上的所有卷根。
	// 不去写别的分区，是因为**客户端对介质全程只读**，这条约束不为例外让路。
	action, err = mergeExemptDiskMarker(filepath.Join(opt.Dest, ".usbbackup-allow-disk"), fpText)
	if err != nil {
		return written, fmt.Errorf("写入磁盘级授权标记失败: %w", err)
	}
	fmt.Fprintf(out, "  [OK] .usbbackup-allow-disk（磁盘级授权标记 → 同物理磁盘所有卷一起豁免；%s）\n", action)
	written++

	// 5) 说明文件（每次都重写，保证与盘内实际内容一致）。
	//    README 必须如实反映私钥是否带口令，否则现场的人会按错误的风险等级处理。
	//    它落在工具目录里，所以文中的相对路径（keys\…）在有无子目录时都成立。
	readme := toolkitReadme(toolkitReadmeInput{
		Fingerprint:      fpText,
		HasPrivate:       opt.WithPrivate,
		PrivateEncrypted: privateIsEncrypted(opt),
		HasCredential:    strings.TrimSpace(opt.CredentialPath) != "",
		CredProtection:   credentialProtection(opt.CredentialPath),
		HasClient:        opt.WithClient,
		GateThreshold:    gateThreshold,
		GateMaxTotal:     gateMaxTotal,
		GateCollect:      gateCollect,
		GateReused:       gateFromExisting,
		UploadEnabled:    gateUpload,
	})
	if err := writeFile(filepath.Join(base, "README.txt"), []byte(readme), true); err != nil {
		return written, fmt.Errorf("写入 README.txt 失败: %w", err)
	}
	fmt.Fprintf(out, "  [OK] %s\n", relOnDisk(opt, "README.txt"))
	written++

	return written, nil
}

// toolkitBaseDir 返回工具实际落盘的目录（= Dest/SubDir）。
func toolkitBaseDir(opt toolkitOptions) (string, error) {
	sub := cleanSubDir(opt.SubDir)
	if sub == "" {
		return opt.Dest, nil
	}
	base := filepath.Join(opt.Dest, sub)
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("创建工具目录 %s 失败: %w", base, err)
	}
	return base, nil
}

// cleanSubDir 规范化并校验 --subdir 的值。
//
// 只接受相对子路径：绝对路径、盘符、以及任何含 `..` 的写法一律拒绝——
// 这个参数来自命令行，放任它逃出盘外就会变成"往任意目录写文件"。
func cleanSubDir(sub string) string {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return ""
	}
	sub = strings.ReplaceAll(sub, "/", string(filepath.Separator))
	sub = filepath.Clean(sub)
	if sub == "." || sub == string(filepath.Separator) {
		return ""
	}
	// `\foo` / `/foo` 在 Windows 上既不是 IsAbs 也没有盘符，
	// 但拼到 `E:` 后面会变成 `E:\foo`——看起来合法，实则指向盘根而非子目录，
	// 与使用者意图不符，直接拒掉。
	if strings.HasPrefix(sub, string(filepath.Separator)) || strings.HasPrefix(sub, "/") {
		return ""
	}
	if filepath.IsAbs(sub) || filepath.VolumeName(sub) != "" {
		return ""
	}
	if sub == ".." || strings.HasPrefix(sub, ".."+string(filepath.Separator)) ||
		strings.Contains(sub, string(filepath.Separator)+"..") {
		return ""
	}
	return sub
}

// mergeExemptMarker 把公钥指纹并入盘根的授权标记文件，**绝不删除已有内容**。
//
// 为什么不直接覆盖：这个文件名与项目 A 共用，而 A 的判定是**逐行比对指纹**
// （`keyfile.MatchAllowMarker`）。同一个盘根完全可能已经躺着 A 写的
// `fingerprint=…`——本项目的工具盘就是这种情况。整体覆盖会让 A 认不出这块盘，
// 于是 A 把它当普通介质扫描、打包、回写——而这块盘里有私钥。
// 一次"顺手覆盖"就能造成私钥外泄，所以这里只追加，永远不替换。
//
// 顺带把它做成幂等的：重复装盘不会越写越长，也不会因为"文件已存在"而失败。
//
// 返回一句动作描述供输出（新建 / 追加 / 已是相同指纹）。
func mergeExemptMarker(path, fingerprint string) (string, error) {
	return mergeMarker(path, fingerprint, func(origin, fp string) string {
		return fmt.Sprintf("# usbbackup-r2 授权标记（卷级）：本卷被豁免，客户端不会采集/上传它的内容\n"+
			"# 生成时间 %s（生成器 %s；%s）\nfingerprint=%s\n",
			time.Now().Format(time.RFC3339), version.Version, origin, fp)
	})
}

// mergeExemptDiskMarker 把公钥指纹并入盘根的**磁盘级**授权标记文件。
//
// 与卷级那份共用同一套"只追加、幂等"的实现，理由也一样（重复装盘不该越写越长），
// 差别只在文件里的说明文字——一个说"本卷豁免"，一个说"整支盘豁免"，
// 免得现场的人看到两行几乎一样的注释却分不清哪个是哪个。
//
// 为什么两个都要写：卷级那份是与项目 A 共用的约定（A 只认它），
// 磁盘级这份是本项目补的多分区缺口（A 不认它）。少了前者，A 会把这块盘当普通介质；
// 少了后者，本项目的客户端会把盘上其它分区采集走。两个都在，才算真的豁免。
func mergeExemptDiskMarker(path, fingerprint string) (string, error) {
	return mergeMarker(path, fingerprint, func(origin, fp string) string {
		return fmt.Sprintf("# usbbackup-r2 授权标记（磁盘级）：**同一物理磁盘上的所有卷**一起被豁免\n"+
			"# 多分区介质（例如 Ventoy 盘）必须靠它：只在某一个分区放卷级标记时，\n"+
			"# 其余分区仍会被采集。本文件放在任意一个分区根目录即可。\n"+
			"# 生成时间 %s（生成器 %s；%s）\nfingerprint=%s\n",
			time.Now().Format(time.RFC3339), version.Version, origin, fp)
	})
}

func mergeMarker(path, fingerprint string, body func(origin, fp string) string) (string, error) {
	old, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		return "新建", os.WriteFile(path, []byte(body("首次写入", fingerprint)), 0o644)
	}

	text := string(old)
	if markerHasFingerprint(text, fingerprint) {
		// 已有相同指纹（另一个项目写的，或本项目的上一次装盘）：一个字都不动。
		// 保住原有内容，比"重写一遍更整齐"重要得多。
		return "已含相同指纹，未改动", nil
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += "\n" + body("追加，原有内容保持不动", fingerprint)
	return "追加", os.WriteFile(path, []byte(text), 0o644)
}

// markerHasFingerprint 判断标记内容里是否已经含有该指纹。
//
// 逐行比对、跳过注释行、剥离 `fingerprint=` / `pubkey:` 这类标签前缀——
// 刻意与项目 A 的解析规则保持一致。两边对"这一行算不算同一个指纹"的理解
// 必须一样，否则会出现"本项目以为写过了、A 却认不出"的错觉。
func markerHasFingerprint(content, fingerprint string) bool {
	want := normalizeFingerprint(fingerprint)
	if want == "" {
		return false
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if normalizeFingerprint(stripMarkerLabel(line)) == want {
			return true
		}
	}
	return false
}

// stripMarkerLabel 剥掉 `fingerprint=` / `pubkey:` 这类标签前缀。
// 只有标签名确实已知时才剥——否则会把指纹自身里的分隔符当标签切坏。
func stripMarkerLabel(line string) string {
	for _, sep := range []string{"=", ":"} {
		i := strings.Index(line, sep)
		if i <= 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(line[:i])) {
		case "fingerprint", "pubkey", "key":
			return strings.TrimSpace(line[i+len(sep):])
		}
	}
	return line
}

// normalizeFingerprint 只保留十六进制字符，用来忽略分组空格与大小写差异。
func normalizeFingerprint(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// relOnDisk 把盘内相对路径显示成"从盘根算起"的形式，方便核对落点。
func relOnDisk(opt toolkitOptions, name string) string {
	if sub := cleanSubDir(opt.SubDir); sub != "" {
		return filepath.Join(sub, name)
	}
	return name
}

// pathOnDisk 拼出盘内文件的完整路径，用于收尾提示。
func pathOnDisk(root, sub, name string) string {
	if sub != "" {
		return filepath.Join(root, sub, name)
	}
	return filepath.Join(root, name)
}

// privateIsEncrypted 判断本次上盘的私钥是否带口令保护。
// 读取失败时按"明文"处理——宁可把风险说重，也不说轻。
func privateIsEncrypted(opt toolkitOptions) bool {
	if !opt.WithPrivate {
		return false
	}
	raw, err := os.ReadFile(opt.PrivateKeyPath)
	if err != nil {
		return false
	}
	return keystore.IsEncryptedPrivateKeyPEM(raw)
}

// credentialProtection 读出凭据的保护方式；读不出来返回空串。
//
// 空串在 README 里会渲染成"保护方式未知"，而不是替它猜一个——
// 猜错的方向恰好是危险的：把机器绑定的写成跨机器可用，现场就会
// 拿着注定解不开的凭据去部署。
func credentialProtection(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	p, err := cred.ProtectionOf(path)
	if err != nil {
		return ""
	}
	return p
}

// protectionShort 把保护方式压成短标签，用于盘内文件清单。
func protectionShort(p string) string {
	switch p {
	case cred.ProtectionDPAPIMachine:
		return "DPAPI 机器绑定，换机失效"
	case cred.ProtectionPassphrase:
		return "口令加密，跨机器可用"
	case cred.ProtectionPlainFile:
		return "未加密，仅靠文件权限"
	case "":
		return "保护方式未知"
	default:
		return p
	}
}

// toolkitReadmeInput 是生成盘内说明文件所需的事实。
//
// 用结构体而不是长参数表：这些字段会随功能增加（容量门控、凭据保护方式
// 都是后加的），而"按位置传一串 bool / string"在这种增长方式下极易错位——
// 把带口令的私钥写成明文只是难听，把机器绑定的凭据写成跨机器可用，
// 会让人在目标机器上白折腾半天。
type toolkitReadmeInput struct {
	// Fingerprint 是公钥指纹文本。
	Fingerprint string
	// HasPrivate 表示盘里是否带私钥。
	HasPrivate bool
	// PrivateEncrypted 表示私钥是否带口令保护。
	PrivateEncrypted bool
	// HasCredential 表示盘里是否带 client.json。
	HasCredential bool
	// CredProtection 是 client.json 的保护方式（cred.Protection* 之一）。
	CredProtection string
	// HasClient 表示盘里是否有 client.exe。
	HasClient bool
	// GateThreshold / GateMaxTotal / GateCollect 是内嵌客户端**实际生效**的值。
	GateThreshold string
	GateMaxTotal  string
	GateCollect   string
	// GateReused 为 true 表示 client.exe 是复用现成的，门控值本命令无从得知。
	GateReused bool
	// UploadEnabled 表示内嵌客户端的上传能力是否开启。
	//
	// 这份 README 是现场唯一的离线读物，"会不会上传"是它最要命的一句话：
	// 写错了，现场就是"跑了半天，R2 上什么都没有"，而且全程不报错。
	// GateReused 为 true 时此字段无意义（取值由那份现成 client.exe 决定）。
	UploadEnabled bool
}

// toolkitReadme 生成盘内说明文件。
//
// 这份文件是**离线**读物：盘插到目标机器上时，现场的人只有它可看。
// 所以凡是"换个机器就会不一样"的事实（凭据是否绑机器、门控到底是多少）
// 都必须写清楚，且必须**如实**——宁可写"未知"，也不要猜一个。
func toolkitReadme(in toolkitReadmeInput) string {
	var b strings.Builder
	b.WriteString("usbbackup-r2 便携工具盘\n")
	b.WriteString("====================\n\n")
	b.WriteString("盘里有什么\n")
	b.WriteString("  usbsetup-r2.exe      交互式生成向导（推荐，双击即问即答）\n")
	b.WriteString("  usbkeygen-r2.exe     生成器（密钥 / R2 凭据 / 客户端 / 工具盘）\n")
	b.WriteString("  usbunseal-r2.exe     解压器（用私钥解密还原，支持从 R2 直接拉取）\n")
	b.WriteString("  usbbackup-r2.exe     主程序 / 客户端模板\n")
	b.WriteString("  usbcomp-r2.exe       独立压缩器（手工打包某个目录）\n")
	if in.HasClient {
		b.WriteString("  client.exe           已内嵌配置与公钥的客户端\n")
	}
	b.WriteString("  install/             安装与卸载（在目标机上跑；详见下方「一键安装」）\n")
	b.WriteString("    install.cmd        零提示安装器：不问任何密钥，自动装机 + 加固 + 设自启\n")
	b.WriteString("    uninstall.cmd      卸载器（双击即彻底卸载：撤加固 + 删服务 + 删目录；\n")
	b.WriteString("                       /KEEP 则只撤加固、保留服务与文件）\n")
	b.WriteString("    client.exe         要装到目标机的客户端（与盘根那份同为内嵌配置版）\n")
	b.WriteString("    client.bin         加密的 R2 凭据（与 .machine.key 配对，装机时解开）\n")
	b.WriteString("    .machine.key       解 client.bin 用的密钥文件（原始字节，不需要人记）\n")
	b.WriteString("    r2perm.py          client.bin 的解密/生成脚本（install.cmd 调用）\n")
	b.WriteString("    usbkeygen-r2.exe   生成器；安装器用它做装后探活\n")
	if in.HasCredential {
		fmt.Fprintf(&b, "  client.json          R2 凭据（%s，见下方说明）\n", protectionShort(in.CredProtection))
	}
	if in.UploadEnabled && !in.HasCredential {
		b.WriteString("  r2.json              凭据素材（**不含 secret**）：目标机器上用它生成 client.json\n")
	}
	b.WriteString("  keys/                密钥材料（见下方风险）\n")
	b.WriteString("  .usbbackup-allow     授权标记（卷级）：本卷被豁免，不会被采集\n")
	b.WriteString("  .usbbackup-allow-disk 授权标记（磁盘级）：同一物理磁盘所有卷一起被豁免\n\n")

	if in.HasClient {
		b.WriteString("client.exe 内嵌的门控（决定什么样的盘会被备份）\n")
		if in.GateReused {
			// 复用现成 client.exe 时本命令改不了内嵌块，也读不出它的值。
			b.WriteString("  这个 client.exe 是现成的、直接装盘的，取值由它自己的内嵌配置决定。\n")
			b.WriteString("  查实际值：client.exe config-check\n\n")
		} else {
			fmt.Fprintf(&b, "  容量阈值        %s\n", emptyOr(in.GateThreshold, "（按内置默认）"))
			b.WriteString("                  这块盘**已占用**超过它 → 整盘跳过，不采集也不上传\n")
			fmt.Fprintf(&b, "  打包体积上限    %s\n", emptyOr(in.GateMaxTotal, "（按内置默认）"))
			b.WriteString("                  本次**待打包**数据量超过它 → 整盘跳过\n")
			fmt.Fprintf(&b, "  采集策略        %s\n", emptyOr(in.GateCollect, "（按内置默认）"))
			b.WriteString("                  all = 未豁免介质一律采集；marker_only = 仅采集标记盘；off = 关闭\n")
			if in.UploadEnabled {
				b.WriteString("  上传到 R2       开启\n")
				b.WriteString("                  产物除了落在本机目录，还会上传到你配置的 R2 桶\n\n")
			} else {
				b.WriteString("  上传到 R2       关闭\n")
				b.WriteString("                  产物**只落本机产物目录，不会上传**。\n")
				b.WriteString("                  要开启：重新装盘并加 --upload（或 build-client 加 --upload）。\n\n")
			}
		}
	}

	b.WriteString("一键安装（推荐：在目标机里直接双击 install\\install.cmd）\n")
	b.WriteString("  install\\install.cmd   本盘自带的安装器。双击即可，会弹 UAC，之后全自动：\n")
	b.WriteString("    1) 把 install\\ 整个复制到 D:\\backup\\usbbackup-r2（服务必须绑本地路径）\n")
	b.WriteString("    2) 逐文件核对副本（文件名 + 大小，缺一个就中止，且不碰本盘）\n")
	b.WriteString("    3) 用 client.bin + .machine.key 解出 R2 凭据 client.json\n")
	b.WriteString("       **全程不问任何密钥**：那把 key 就是一个随盘走的文件，没什么要记的\n")
	b.WriteString("    4) 完成首次知情确认、注册服务、设开机自启 + 崩溃自动重启\n")
	b.WriteString("    5) 联网探活一次，证明凭据真能上传（--timeout 1）\n")
	b.WriteString("    6) 最后给 D:\\backup 加\"拒绝删除\"加固（保留可读，服务不受影响）\n")
	b.WriteString("  卸载：install\\uninstall.cmd   双击即可，不带参数就是彻底卸载\n")
	b.WriteString("        （撤加固 + 删服务 + 删目录）；/KEEP 只撤加固、保留服务与文件。\n")
	b.WriteString("        它跑完会自己回读一遍结果：服务与目录都真没了才报 [OK]，\n")
	b.WriteString("        否则逐条列出残留和下一步——不会只喊一句 DONE 就收工。\n")
	b.WriteString("  开关：\n")
	b.WriteString("    /DRYRUN   只打印计划，什么都不改        /NOAUTH   跳过凭据步骤\n")
	b.WriteString("    /NOVERIFY 跳过联网探活                  /NOHARDEN 不加\"拒绝删除\"\n")
	b.WriteString("    /CLEAN    先清空目标目录再装（连旧凭据一起删）\n")
	b.WriteString("    /UNDO     撤销加固与失败重启策略\n")
	b.WriteString("    /PURGE    /UNDO 之外再卸载服务、删除 D:\\backup\\usbbackup-r2\n")
	b.WriteString("  [!] 凭据是**明文**（plain-file-0600），而且**每台机器都一样**——这是为了\n")
	b.WriteString("      免去逐台输密钥的代价。它随盘走，所以：别把这个盘交给别人；\n")
	b.WriteString("      要轮换就重新生成一份 client.bin 再跑一次安装器。\n")
	b.WriteString("  [!] 加固期间不能升级/迁移/卸载工具，要先跑 /UNDO。这条加固只拒绝删除\n")
	b.WriteString("      （Delete + DeleteSubdirectoriesAndFiles），不影响读取——服务照常读得到\n")
	b.WriteString("      client.json。\n")
	b.WriteString("  [!] 别在盘上直接跑 client.exe：install-service 会把服务绑死在盘符上，拔盘\n")
	b.WriteString("      即失效。install\\install.cmd 就是为了解决这件事。\n")
	b.WriteString("\n手动安装（不用脚本，逐个命令跑）\n")
	b.WriteString("  【强烈建议】先把工具拷到目标机的本地目录再跑，例如 C:\\backup-agent。\n")
	if in.HasCredential {
		b.WriteString("  直接在盘上跑有两个硬伤：install-service 会把服务绑死在盘符上（拔盘即失效），\n")
		b.WriteString("  而且客户端会优先读盘上这份 client.json —— 它会把你在本地生成的凭据盖掉。\n")
	} else {
		// 盘上没有 client.json 时不能照搬上面那句：本盘只有素材（r2.json），
		// 没有可"抢先"的凭据。写了会让人去找一个不存在的文件。
		b.WriteString("  直接在盘上跑有一个硬伤：install-service 会把服务绑死在盘符上（拔盘即失效）。\n")
	}
	b.WriteString("  （U 盘只当分发介质。）\n")
	if in.HasCredential && in.CredProtection == cred.ProtectionPassphrase {
		b.WriteString("  0) 先让客户端能**读到凭据口令**。漏掉这一步不会报错，但上传会被跳过、\n")
		b.WriteString("     产物只落在本机 —— 现场表现为\"跑了半天，R2 上什么都没有\"：\n")
		b.WriteString("       把口令单独写成一个文件（别放本盘、别和客户端同目录），然后\n")
		b.WriteString("         setx USBBACKUP_R2_CRED_PASSPHRASE_FILE \"C:\\ProgramData\\usbbackup-r2\\cred.pass\"\n")
		b.WriteString("       要注册成服务的话，服务以 LocalSystem 运行，**用户级变量它看不见**，\n")
		b.WriteString("       必须用管理员权限 `setx /M ...` 设成系统级变量，再装服务。\n")
		b.WriteString("       验证：client.exe cred-check 应能解开凭据并列出端点/桶/前缀。\n")
		b.WriteString("       （客户端只认上面两个环境变量，**没有** --cred-pass-file 开关；\n")
		b.WriteString("         --cred-pass-file 是生成器与解密器的参数。）\n")
		b.WriteString("       不想每次都给口令？见下面「关于 client.json」里的 DPAPI 做法。\n")
	}
	if in.UploadEnabled && !in.HasCredential {
		b.WriteString("  0) 先在本机生成一份凭据——上传能力已开，但盘上**没有**凭据。\n")
		b.WriteString("     跳过这步的现场表现是\"跑了半天，R2 上什么都没有\"，而且不报错。\n")
		b.WriteString("     做法见本文件下面「关于 R2 凭据」一节，三步。\n")
	}
	b.WriteString("  1) 在本地目录里运行 client.exe accept   ← 首次确认一次\n")
	b.WriteString("  2) 运行 client.exe run                  ← 之后静默常驻\n")
	if in.UploadEnabled {
		b.WriteString("  3) 密文产物 .usbk 会自动上传到 R2；也可以手工补传：\n")
		b.WriteString("     usbbackup-r2.exe upload <文件>.usbk\n")
	} else {
		b.WriteString("  3) **上传是关闭的**（内嵌 upload.enabled=false）：密文产物只落在本机，\n")
		b.WriteString("     不会上传。想上传要重新装盘并加 --upload，见上面「内嵌的门控」。\n")
	}
	b.WriteString("  4) 在放有私钥的机器上取回并解密：\n")
	b.WriteString("     usbunseal-r2.exe pull --out <目录> --key keys\\usbbackup-r2.key.pem --cred client.json\n")
	b.WriteString("     （--cred 省略时会依次找 .\\client.json 与 %LOCALAPPDATA%\\usbbackup-r2\\client.json）\n")
	b.WriteString("     私钥带口令时追加 --pass（交互式）或 --pass-file <口令文件>\n\n")
	b.WriteString("为什么这个盘不会被采集走\n")
	b.WriteString("  盘根有两个授权标记（内容都是指纹）：\n")
	b.WriteString("    .usbbackup-allow       客户端读到的卷 → **该卷**豁免\n")
	b.WriteString("    .usbbackup-allow-disk  客户端读到它 → **同一物理磁盘上的所有卷**豁免\n")
	b.WriteString("  客户端读到就知道「这是自己人的盘，里面甚至有私钥」，于是不读取、不打包、\n")
	b.WriteString("  不上传。这条判定不受采集策略影响——哪怕策略是 all 也一样豁免。\n")
	b.WriteString("  为什么要有第二个：多分区介质（U 盘里很常见，Ventoy 盘必然如此）如果只在\n")
	b.WriteString("  主分区放标记，另一个分区就会被当成陌生介质整盘打包上传。磁盘级标记把\n")
	b.WriteString("  豁免范围提到「这支盘」，与人的直觉一致。判定时客户端会去查同一个物理\n")
	b.WriteString("  磁盘上的所有卷根，所以只需要在主分区的盘根放这一个文件。\n")
	b.WriteString("  注意：卷级那个文件名与不含出站能力的版本共用，装盘时只**追加**指纹、\n")
	b.WriteString("  从不覆盖——覆盖会把另一个项目写的指纹冲掉，那一边的客户端就会\n")
	b.WriteString("  反过来采集这块盘。磁盘级那个是本项目新增的，另一个版本不认它，\n")
	b.WriteString("  但也不受影响（它只看前者）。\n\n")
	b.WriteString("公钥指纹\n")
	fmt.Fprintf(&b, "  %s\n\n", in.Fingerprint)

	if in.HasCredential {
		b.WriteString("关于 client.json（R2 凭据）\n")
		switch in.CredProtection {
		case cred.ProtectionDPAPIMachine:
			b.WriteString("  它用 Windows DPAPI 的**机器范围**密钥加密，因此：\n")
			b.WriteString("  - 在这一台电脑上生成的，拿到别的机器上解不开（这是设计意图，不是故障）；\n")
			b.WriteString("  - 换机器/重装系统后，在目标机器上重新执行 usbkeygen-r2 cred 生成一份。\n")
		case cred.ProtectionPassphrase:
			b.WriteString("  它是**口令加密**的（PBKDF2-SHA256 60 万次 + AES-256-GCM），不绑定机器：\n")
			b.WriteString("  - 任何 Windows 机器上都能用，代价是每次运行都要能拿到口令；\n")
			b.WriteString("  - **客户端只认环境变量**（它没有 --cred-pass-file 这个开关）：\n")
			b.WriteString("      USBBACKUP_R2_CRED_PASSPHRASE_FILE=<含口令的文件>   ← 推荐，注意文件权限\n")
			b.WriteString("      USBBACKUP_R2_CRED_PASSPHRASE=<口令原文>          ← 次选，会进进程环境\n")
			b.WriteString("    解密器另有 --cred-pass-file，也可以写进它自己的配置文件；\n")
			b.WriteString("  - 口令**没有写在盘上**（按设计）。盘与口令同时丢失 = R2 凭据泄漏，\n")
			b.WriteString("    但备份本身仍然解不开——解密还需要私钥口令。\n")
			b.WriteString("\n  不想每次都给口令？换成 DPAPI 机器绑定档即可（**每台机器少一步**）：\n")
			b.WriteString("     把工具拷到本地目录（如 C:\\backup-agent），在那里执行\n")
			b.WriteString("       usbkeygen-r2.exe cred --from r2.json --out client.json --scope upload --force\n")
			b.WriteString("     （客户端只需上传权限；解密器要另出一份 --scope both 的凭据，别共用）\n")
			b.WriteString("     不带 --cred-pass-file / --cred-pass / --plain-file 时默认就是 DPAPI 档；\n")
			b.WriteString("     之后不设任何环境变量，client.exe cred-check 也应能列出生效凭据。\n")
			b.WriteString("     代价：凭据与本机绑定，重装系统/换机要重生成一份。\n")
			b.WriteString("     注意：必须先把盘上这份 client.json 挪开或换目录——客户端找凭据的顺序是\n")
			b.WriteString("     client.exe 同级 → 当前目录 → %LOCALAPPDATA%\\usbbackup-r2\\，盘上那份会抢先。\n")
		case cred.ProtectionPlainFile:
			b.WriteString("  [!] 它是**明文**凭据，只靠文件权限保护：\n")
			b.WriteString("  - 拿到盘就能直接用这份凭据读写/删除远端对象；\n")
			b.WriteString("  - 客户端与服务**会自动放行读取**（无人值守，没有控制台可交互），\n")
			b.WriteString("    只在日志里留一条 WARN；交互式命令仍要显式加 --allow-plain-cred。\n")
		default:
			b.WriteString("  它的保护方式**未能识别**（可能是更新版本写的文件），请自行确认后再用。\n")
		}
		b.WriteString("  两点与保护方式无关，但要知道：\n")
		b.WriteString("  - 泄漏时的处置是「控制台吊销 token + 换一份凭据」，**不需要**重新编译客户端；\n")
		b.WriteString("  - token 请用「Object Read & Write + 仅限目标桶」，不要用 Admin 两档；\n")
		b.WriteString("    R2 没有「只写不读」这一档，也不能把长效 token 限定到 key 前缀，\n")
		b.WriteString("    所以这一档同时能读/覆盖/删除，而 R2 没有对象版本控制 —— 删除**没有原生兜底**，\n")
		b.WriteString("    请定期轮换 token，并自行评估远端对象被删除的风险。\n\n")
	} else if in.UploadEnabled {
		// 上传开着、盘上没有明文的 client.json。这是工具盘的常规形态：凭据以
		// install\client.bin 的形式随盘分发，装机时用 .machine.key 解开。
		// 必须把这条讲清楚，否则现场只知道"上传开着"，却不知道凭据从哪来，
		// 最后表现还是"跑半天 R2 上什么都没有"。
		b.WriteString("关于 R2 凭据（以 install\\client.bin 随盘分发）\n")
		b.WriteString("  上传能力已开启，凭据**预先离线生成好**，放在 install\\ 里，装机时\n")
		b.WriteString("  自动解开成 client.json。**全程不需要输入任何密钥**——这不是「忘了」，\n")
		b.WriteString("  而是刻意的部署取舍：\n")
		b.WriteString("    · 那把 .machine.key 就是一个随盘走的文件，没什么可记、也没什么可输；\n")
		b.WriteString("    · 代价是这份凭据**每台机器都一样**，而且解出来是**明文**\n")
		b.WriteString("      （保护方式 plain-file-0600，只有文件权限这一层）。\n")
		b.WriteString("  因此：别把这块盘交给别人；要轮换就重新生成一份 client.bin 再装一次。\n\n")
		b.WriteString("  重新生成凭据（在联网的机器上，需要 token value）：\n")
		b.WriteString("    cd <本盘>\\install\n")
		b.WriteString("    python r2perm.py build --token-value <token> --out client.json\n")
		b.WriteString("    python r2perm.py shield --in client.json --key .machine.key --out client.bin\n")
		b.WriteString("  （build 也可用 --from r2.json / 环境变量取 token；见 r2perm.py --help）\n")
		b.WriteString("\n  如果拿到的是**明文 client.json**，那更简单——install.cmd 会直接用它，\n")
		b.WriteString("  省掉解 client.bin 这一步。此时要自己保证文件权限收紧（0600）。\n")
		b.WriteString("\n  两条与保护方式无关、但要知道：\n")
		b.WriteString("  - 客户端**只认 client.json 这一份外部文件**（config.json 与环境变量一律忽略）；\n")
		b.WriteString("    查凭据的顺序是 client.exe 同级 → 当前目录 → %LOCALAPPDATA%\\usbbackup-r2\\；\n")
		b.WriteString("  - 装完想确认凭据真的生效，在目标机上跑：\n")
		b.WriteString("      client.exe cred-check      ← 本地解密检查，不发网络请求\n")
		b.WriteString("      client.exe config-check    ← 环境 + 上传通道一栏\n")
		b.WriteString("    两条都应报成功；只有 WARN 说「凭据未加密」是预期的。\n")
		b.WriteString("  - token 请用「Object Read & Write + 仅限目标桶」，不要用 Admin 两档，\n")
		b.WriteString("    并定期轮换；R2 没有对象版本控制，删除**没有原生兜底**。\n\n")
	}
	b.WriteString("产物、日志与审计落在哪\n")
	b.WriteString("  客户端内嵌的配置里，这些路径存的是**模板**（%TEMP% / %LOCALAPPDATA%），\n")
	b.WriteString("  在目标机器上运行时才解析成真实路径——所以换台机器不用重新生成二进制。\n")
	b.WriteString("  产物输出目录    %TEMP%\\backup\n")
	b.WriteString("  日志与审计      %LOCALAPPDATA%\\usbbackup-r2\\（usbbackup-r2.log / audit.jsonl）\n")
	b.WriteString("  [!] 这里的 %LOCALAPPDATA% 是**跑进程那个账户**的，不是你登录账户的。\n")
	b.WriteString("      服务以 LocalSystem 运行，它的 %LOCALAPPDATA% 是\n")
	b.WriteString("      C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local —— 去自己的\n")
	b.WriteString("      C:\\Users\\<你>\\AppData\\Local\\usbbackup-r2\\ 找服务日志是找不到的。\n")
	if in.UploadEnabled {
		b.WriteString("  上传成功之后本地产物会被删除，R2 上那份是唯一副本。\n\n")
	} else {
		b.WriteString("  上传未开启，产物只留在本机（不会被删除）。\n\n")
	}
	if in.HasPrivate && in.PrivateEncrypted {
		b.WriteString("[!] 私钥风险（口令保护）\n")
		b.WriteString("  keys\\usbbackup-r2.key.pem 带口令保护：不知道口令则无法解开。\n")
		b.WriteString("  但口令保护不等于安全——盘和口令同时丢失就等于明文丢失：\n")
		b.WriteString("  - 不要把口令写在这个盘上的任何文件里（包括本文件）；\n")
		b.WriteString("  - 不要把这个盘插到不受你控制的机器上；\n")
		b.WriteString("  - 解密时会提示输入口令（usbunseal-r2 --pass）。\n")
	} else if in.HasPrivate {
		b.WriteString("[!] 私钥风险（明文，高风险）\n")
		b.WriteString("  keys\\usbbackup-r2.key.pem 是**明文私钥**，拿到盘就能解密：\n")
		b.WriteString("  - 盘丢了 = 所有用对应公钥加密的备份都能被解开；\n")
		b.WriteString("  - 不要把这个盘插到不受你控制的机器上；\n")
		b.WriteString("  - 更稳妥的做法：换成带口令的私钥，或只带公钥（--without-private 重装）。\n")
	} else {
		b.WriteString("本盘只带公钥，私钥未上盘：解密时需要从你的电脑取私钥。\n")
	}
	fmt.Fprintf(&b, "\n生成于 usbbackup-r2 %s\n", version.Version)
	return b.String()
}

// ---- 小工具 ----

func exeDirOf() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func emptyOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func copyFile(src, dst string, force bool) error {
	if !force {
		if _, err := os.Stat(dst); err == nil {
			return fmt.Errorf("%s 已存在（加 --force 覆盖）", dst)
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func writeFile(path string, body []byte, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s 已存在（加 --force 覆盖）", path)
		}
	}
	return os.WriteFile(path, body, 0o644)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
