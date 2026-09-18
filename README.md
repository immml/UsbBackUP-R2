# usbbackup-r2

Windows 专用的 **U 盘自动采集 → 整盘打包 → 混合加密 → 自动上传对象存储** 工具。三件套：**客户端**（在目标机器上跑）、**生成器**（在你手里）、**解密器**（在你手里）。

- **零第三方依赖**：只用 Go 标准库，R2 的 SigV4 签名是手写的（不引 AWS SDK），可离线构建。
- **纯 Windows**：只针对 Windows amd64，用 Win32 API。
- **源介质只读**：全程不写入、不删除、不改名被采集盘上的任何文件。

> ⚠️ **使用前必读**：本工具会对接入本机的可移动介质执行**自动**读取与打包，
> 并把加密产物**上传到你在配置里指定的 Cloudflare R2 桶**。
> 请先完整阅读 [DISCLAIMER.md](DISCLAIMER.md) 与本文档的「安全提示」一节。
> **仅限用于你自己拥有或完全管理的机器，以及你自己拥有的可移动介质。**
>
> 🚀 **第一次用？先看 [TUTORIAL.md](TUTORIAL.md)**（从生成密钥到还原文件的完整实操）。

---

## 0. 这是一个独立项目

本仓库是 [UsbBackUP](https://github.com/immml/UsbBackUP)（不含任何出站能力的那一版）的**独立分支**，不是它的补丁，也不共享 module。两者刻意保持一致的东西：

| 共用 | 值 |
|---|---|
| 容器格式 | 魔数 `USBK`、`Version=1`、`OAEPLabel="usbbackup/v1"`、96 字节固定头 |
| 授权标记 | `.usbbackup-allow`（两边同名，工具盘互相认） |
| 命令行约定 | 全局开关 `--config` / `--yes`、退出码语义、`I AGREE` 首启确认 |

刻意分开的东西：

| | `UsbBackUP` | 本仓库 |
|---|---|---|
| 出站网络 | **零网络** | 仅到配置的 R2 endpoint 的 HTTPS |
| 私钥回写分支 | 有 | **已移除** |
| 产物去向 | 只留本机 `%TEMP%\backup` | 上传到 R2（也可只留本地） |
| 解密方式 | 手工把 `.usbk` 拷回来 | 解密器直接从 R2 拉取并解密 |
| 程序集名 / 服务名 | `usbbackup` | `usbbackup-r2` |
| 配置目录 | `%LOCALAPPDATA%\usbbackup\` | `%LOCALAPPDATA%\usbbackup-r2\` |
| 环境变量前缀 | `USBBACKUP_*` | `USBBACKUP_R2_*` |
| 密钥默认名 | `usbbackup.key.pem` / `.pub.pem` | `usbbackup-r2.key.pem` / `.pub.pem` |
| 可执行文件 | `usbbackup` / `usbkeygen` / `usbsetup` / `usbcomp` / `usbunseal` | 各自加 `-r2` 后缀 |

所以**两者可以装在同一台机器上**：服务名、配置目录、环境变量、密钥文件名全部独立，谁都不会覆盖谁。**唯一故意同名的是授权标记**——两个项目的工具盘都要被对方认出来是"自己人的盘"，名字不同反而会互相采集。

**容器格式保持一致**：label 是**格式标识**而非产品标识，改它等于凭空造出一个不兼容格式，还得同步递增容器版本号——没有收益，所以不改。两个项目产出的 `.usbk` 互相可解。

> 别把两套工具混装进同一个目录。名字只差一个后缀，行为却不同，拿错很自然。

---

## 1. 它做什么

### 三个角色

```
       你（生成器）                          目标机器（客户端）              你（解密器）
 ┌───────────────────────┐          ┌──────────────────────────┐   ┌──────────────────────┐
 │ usbkeygen-r2          │          │ client.exe               │   │ usbunseal-r2         │
 │  · generate  生成密钥 │  ──部署──▶│  · 内嵌配置 + 公钥       │   │  · remote  列远端    │
 │  · cred      生成凭据 │          │  · 插盘后自动采集        │   │  · pull   下载+解密  │
 │  · build-client 产客户端│        │  · 打包 → 加密 → 上传    │   │     用本机私钥       │
 │  · install-usb 装工具盘│          │  · 只持有**公钥**        │   │  · 需要**私钥**      │
 └───────────────────────┘          └──────────────────────────┘   └──────────────────────┘
            私钥从不离开你                                                 ↑
                                   ┌──────────────┐                      │
                                   │  Cloudflare  │──────────────────────┘
                                   │  R2 桶       │  下载密文（.usbk）
                                   └──────────────┘
```

**私钥永远只在"你的机器"上**：客户端只内嵌公钥，它能加密、不能解密。所以客户端（连同它内嵌的公钥）落在别人手里也不会泄露任何历史备份。

### 插入 U 盘后做什么

```
卷到达事件
  │
  ├─ 卷就绪等待（刚插入时卷可能还没挂载完）
  │
  ├─ 卷类型检查 ── 非可移动卷 → 跳过（除非显式 --allow-fixed，仅供排障）
  │
  ├─ 盘根有 .usbbackup-allow ？ ── 有 → **豁免**，直接结束
  │                                    （不读、不打包、不上传；任何策略档位都不能绕过）
  │
  ├─ 采集策略判定
  │    all          → 放行
  │    marker_only  → 只有盘根带 .usbbackup-collect 才放行
  │    off          → 跳过
  │
  ├─ 容量门控 ── 已占用 > 阈值 → 跳过
  │
  └─ 整盘 zip 流式直送混合加密（明文 zip 不落盘）
       │
       ├─ 上传到 R2（可选）→ HEAD 核对远端大小 → 按配置删/留本地密文
       │
       └─ 审计记录（一行 JSON）
```

**全程对源介质只读**。唯一的写动作落在本机产物目录与远端对象存储上。

### 关键行为约定

- 明文 zip **不落盘**：打包与加密用管道直接串起来，中间只有密文落盘（决策 D-03）。
- 上传失败**不把整次作业判成失败**：本地已经有一份完好的密文，判失败会让人以为数据丢了。处置是保留本地 + 记审计 + 用 `upload` 子命令补传。
- 凭据不可用时**明确报错并退回"仅本地产物"模式**，不静默降级。
- 审计记录**只有盘符、卷标、容量、分支、布尔判定与计数**，没有文件名、没有清单、没有内容、没有 token。
- 远端对象键带 UTC 时间戳（`usb/20260918T143739Z_<卷标>.zip.usbk`）：同一块盘的多次采集互不覆盖。远端没有本地的冲突改名逻辑，重名就是静默覆盖上一次的备份。

---

## 2. 加密方案

单一容器文件 `.usbk`：

| 层级 | 算法 | 说明 |
|---|---|---|
| 会话密钥包装 | RSA-OAEP（SHA-256） | 用公钥包装一把随机的 AES-256 密钥 |
| 数据加密 | AES-256-GCM | 分块，每块独立 nonce；篡改与截断都会导致解密失败 |
| 密钥长度 | 默认 4096 位（下限 2048，上限 8192） | |

容器头 96 字节里含公钥指纹，所以**不需要私钥就能确认这份密文是给哪把密钥的**。指纹只标识密钥身份，不泄露任何密钥材料。

解密失败时不区分"密钥不对"与"数据被篡改"——避免把校验信息变成攻击者的反馈渠道。

---

## 3. 安装与构建

### 3.1 预编译产物

`dist/` 下有五个 exe，全部是 `windows/amd64`（`usbbackup-r2.exe` 用 `-H windowsgui`，常驻时不弹控制台窗口）：

| 程序 | 作用 |
|---|---|
| `usbbackup-r2.exe` | 主程序 / 客户端（常驻监控） |
| `usbkeygen-r2.exe` | 生成器（密钥、凭据、客户端、工具盘） |
| `usbsetup-r2.exe` | 交互式向导（不想记参数就用它） |
| `usbunseal-r2.exe` | 解密器（含从 R2 拉取） |
| `usbcomp-r2.exe` | 压缩器（手工打包任意目录） |
| `client.exe` | 生成器产出的客户端（内嵌配置与公钥），**不是构建产物** |

另有交叉编译产物 `dist/usbunseal-r2-linux-amd64` / `-arm64`（ELF，原生可执行，见 [4.3.1](#431-在-linux-上取回备份)）。

### 3.2 从源码构建

需要 Go 1.24+，无第三方依赖，可离线构建。

```PowerShell
# Windows / PowerShell
cd D:\Users\flowe\WorkBuddy\渗透\usbguard-r2
.\build.ps1                 # 全部编到 .\dist\
.\build.ps1 -Clean          # 先清掉 dist\
```

```bash
# Linux（含 WSL / Git Bash）：交叉编译 Windows 五件套 + Linux 解密器
cd /d/Users/flowe/WorkBuddy/渗透/usbguard-r2
./build.sh                  # 只出 Windows 五件套
./build.sh linux            # 额外出 linux/amd64 + linux/arm64 的 usbunseal-r2（并校验 ELF 魔数）
./build.sh -t               # 先跑 gofmt + go vet + go test
```

---

## 4. 使用

### 4.1 完整流程（推荐路径）

#### 第一步：生成密钥对（在你的机器上）

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbkeygen-r2.exe generate --out .\keys --pass
```

`--pass` 会交互式要一个口令来保护私钥（无回显）。生成后 **立刻离线备份私钥与口令**——私钥丢了，密文就永远解不开了。

#### 第二步：生成 R2 凭据（在你的机器上）

先到 Cloudflare 控制台建一个 API token（权限要求见 §5.1），然后：

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbkeygen-r2.exe cred `
  --out .\client.json `
  --account-id aacbb6abba999cde14c3ddcce80ec425 `
  --bucket usbbackup `
  --prefix usb/ `
  --access-key-id <Access Key ID> `
  --label "office-pc 的上传凭据"
# Secret Access Key 会交互式询问（无回显）；不要写在命令行上
```

生成完立刻验一下：

```PowerShell
# PowerShell
..\dist\usbkeygen-r2.exe r2-check --cred-file .\client.json
```

`r2-check` 依次检查：写入对象 → 读回元数据 → 清理探活对象 → **权限范围**（用 `ListBuckets` 判断 token 是不是账户级 Admin，是就报 WARN）。

> **默认的凭据是 DPAPI 机器范围加密的**：在这一台电脑上生成的，拿到别的电脑上解不开。这是设计意图，不是故障。**部署到哪台机器，就在哪台机器上生成一份 `client.json`。**
>
> 例外是"要拿到 Linux 上用"：Linux 没有 DPAPI，读不了这种凭据。给 Linux 的那一份必须加 `--cred-pass-file`（口令加密）或 `--plain-file`（明文，最后手段）。**同一条 R2 token 可以生成多份凭据，保护方式各选各的**——客户端那份用 DPAPI，解密器那份用口令，互不影响。

#### 第三步：产出客户端

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbkeygen-r2.exe build-client `
  --public .\keys\usbbackup-r2.pub.pem `
  -o .\client.exe `
  --template ..\dist\usbbackup-r2.exe `
  --output-dir "%TEMP%\backup" `
  --threshold 10GiB `
  --name "office-pc" `
  --collect all `
  --upload `
  --cred-name client.json
```

产出的是**单个 exe**：配置与公钥内嵌在 PE 文件尾部的 overlay 块里（带 SHA-256 校验），不需要再分发配置文件。`--no-upload` 可以显式关掉上传（只落本地）。

不想记参数就用向导：

```PowerShell
# PowerShell
..\dist\usbsetup-r2.exe
```

#### 第四步：部署到目标机器

把 `client.exe` 与 `client.json` **放在同一个目录**，然后：

```CMD
REM 目标机器 · CMD（管理员）
cd C:\backup-agent
client.exe accept --yes
client.exe run
```

`accept` 只需做一次（首次会展示完整安全警告并要 `I AGREE`）。之后 `run` 静默常驻。

想让它开机自动跑，注册成服务（需管理员）：

```CMD
REM 目标机器 · CMD（管理员）
client.exe install-service
client.exe start
client.exe status
```

> 服务模式下 `%LOCALAPPDATA%` 指向的是**系统配置目录**，不是用户目录。部署时一律用**绝对路径**，别依赖环境变量展开。

#### 第五步：取回并解密（在你的机器上）

```PowerShell
# PowerShell（放着私钥的那台机器）
cd D:\backup
..\dist\usbunseal-r2.exe init --cred .\client.json --key .\keys\usbbackup-r2.key.pem --out-dir D:\restore
..\dist\usbunseal-r2.exe ls                                  # 看看远端有什么
..\dist\usbunseal-r2.exe pull --pass                          # 取最新一个并解密
```

`pull` 默认只取**最新一个**对象（对应"我刚插过一次盘"这个最常见的场景）；要补历史加 `--all`。下载 → 校验容器头 → 解密 → 解压，一条命令走完，中间产物放临时目录、用完即删。

想改成"在 Linux 上取回"，见 [4.3.1](#431-在-linux-上取回备份)。

### 4.2 生成器 `usbkeygen-r2`

| 子命令 | 作用 |
|---|---|
| `generate` | 生成 RSA 密钥对（`--bits` / `--pass` / `--pass-file` / `--out` / `--force`） |
| `use <公钥>` | 把已有公钥登记进配置 |
| `inspect <公钥>` | 看位数与指纹 |
| `selftest` | 就地跑一遍加密→解密往返，不落盘 |
| `cred` | 生成 `client.json`：默认 DPAPI；`--cred-pass-file` / `--cred-pass` 出口令加密（跨平台）；`--plain-file` 出明文 |
| `r2-check` | 用凭据做一次探活 + 权限范围检查 |
| `build-client` | 产出内嵌配置与公钥的客户端 exe |
| `install-usb` | 组装一个便携工具 U 盘 |
`build-client` 的覆盖项：`--output-dir` / `--threshold` / `--max-total` / `--collect` / `--upload` / `--no-upload` / `--cred-name` / `--name`。客户端模式**忽略**外部 config.json 与环境变量——否则"硬编码配置"就能靠改配置绕过去。

### 4.3 解密器 `usbunseal-r2`

命令行风格刻意对齐 `git`：`init` 生成配置、`config` 查看配置、`ls` 列远端、`pull` 取回并解密。

| 子命令 | 需要私钥 | 作用 |
|---|---|---|
| `init` | 否 | 生成配置骨架（只登记路径与开关，**不含任何凭据材料**） |
| `config` | 否 | 打印生效配置 + 关键文件是否存在 + 凭据保护方式 |
| `ls [前缀]` | 否 | 列出远端对象（相当于 `git ls-remote`，需要可读的凭据） |
| `pull [对象键]` | 是 | 从 R2 下载 + 解密 + 解压（相当于 `git pull`） |
| `list <文件.usbk>` | 否 | 只读容器头：版本、算法、公钥指纹、分块数 |
| `verify <文件.usbk> --key <私钥>` | 是 | 校验完整性，不解出明文 |
| `unseal <文件.usbk> -d <目录> --key <私钥>` | 是 | 解密并解压本地容器 |

`pull` 的常用开关：`--latest`（默认）/ `--all` / `--object <键>` / `--skip-existing`（默认开，重跑幂等）/ `--keep-container`（保留下载的密文）/ `--delete-remote`（解密成功后删远端，默认不动）/ `--dry-run`。

配置默认在 `~/.config/usbbackup-r2/unseal.json`（Windows 上为 `%AppData%\usbbackup-r2\unseal.json`）：

```json
{
  "format": "usbbackup-r2-unseal/v1",
  "scheme_version": 1,
  "prefix": "usb/",
  "cred_file": "/home/me/.config/usbbackup-r2/client.json",
  "cred_pass_file": "/home/me/.config/usbbackup-r2/cred.pass",
  "key_file": "/home/me/.config/usbbackup-r2/usbbackup-r2.key.pem",
  "key_pass_file": "/home/me/.config/usbbackup-r2/key.pass",
  "out_dir": "/home/me/usb-restore",
  "skip_existing": true
}
```

生成时可以直接把这些填进去，不必手改 JSON：

```Linux
usbunseal-r2 init --cred ~/.config/usbbackup-r2/client.json \
  --cred-pass ~/.config/usbbackup-r2/cred.pass \
  --key  ~/.config/usbbackup-r2/usbbackup-r2.key.pem \
  --key-pass ~/.config/usbbackup-r2/key.pass \
  --out-dir ~/usb-restore
```

`init` 会当场检查两件最容易漏的事：**凭据是口令加密但 `cred_pass_file` 是空的**、**私钥带口令但 `key_pass_file` 是空的**——这两种配置注定跑不起来。

#### 4.3.1 在 Linux 上取回备份

取回备份的人通常不在生成备份的那台 Windows 机器前，所以解密器提供 `linux/amd64` 与 `linux/arm64` 两个原生产物（`./build.sh linux` 产出，`dist/usbunseal-r2-linux-*`）。注意**只有解密器参与交叉编译**：其余四件依赖 Windows 专有的卷/服务 API。

Linux 上没有 DPAPI，因此有一条硬约束：

> **DPAPI 保护的 `client.json` 在 Linux 上读不了。** 要给 Linux 用的凭据必须用口令加密生成。

完整流程（在一台 Linux 机器上，比如树莓派）：

```Linux
# 1) 在 Windows 生成器上产出一份"跨平台可读"的凭据（口令从文件读，不上命令行）
#    PowerShell：
#    usbkeygen-r2 cred --out .\client.json --cred-pass-file .\cred.pass

# 2) 把用得到的东西拷到 Linux：
#    client.json（口令加密）、cred.pass（口令文件）、私钥、usbunseal-r2-linux-*
#    Windows 上产出的文件没有可执行位，且 ls 在 NTFS 上不会显示它——
#    拷完补一次，或改用 tar/scp -p 保持权限：
tar -cf - usbunseal-r2-linux-amd64 | ssh box 'tar -xf -'      # 保持权限的拷法
chmod +x usbunseal-r2-linux-amd64
chmod 600 cred.pass key.pass client.json

# 3) 生成配置并取回
./usbunseal-r2-linux-amd64 init --cred ~/.config/usbbackup-r2/client.json \
  --cred-pass ~/.config/usbbackup-r2/cred.pass \
  --key ~/.config/usbbackup-r2/usbbackup-r2.key.pem
./usbunseal-r2-linux-amd64 config     # 先看清生效配置与凭据保护方式
./usbunseal-r2-linux-amd64 ls         # 列出远端有哪些产物
./usbunseal-r2-linux-amd64 pull       # 取最新一个并解密解压
```

嫌名字长就改名成 `usbunseal-r2` 放进 `PATH`（`mv usbunseal-r2-linux-amd64 ~/bin/usbunseal-r2`）。

口令文件的替代来源（适合 systemd / 脚本）：环境变量 `USBBACKUP_R2_CRED_PASSPHRASE`、`USBBACKUP_R2_CRED_PASSPHRASE_FILE`。两者都**不如口令文件**——`/proc/<pid>/environ` 对同机同用户与 root 可读，`ps eww` 也可能带出来。单用户机器可以接受，多用户机器请用 `cred_pass_file`。

### 4.4 主程序 `usbbackup-r2`（同时也是客户端）

| 子命令 | 作用 |
|---|---|
| `run` | 前台常驻（事件驱动为主，轮询兜底） |
| `once --drive E:` | 对指定盘符执行一次 |
| `list [--all]` | 列出卷与容量 |
| `probe --drive E:` | 只读诊断：这个盘会被怎么处理（不写数据、不发请求） |
| `upload <产物.usbk>` | 手工补传本地产物到 R2 |
| `cred-check` | 检查 `client.json` 能否在本机解开 |
| `config-check` | 校验配置与运行环境 |
| `install-service` / `start` / `stop` / `status` | 服务管理（需管理员） |
| `accept` | 首次知情同意 |
| `version` | 版本信息 |

`upload` 只接受本工具产出的 `.usbk`（会校验容器魔数）——免得它被当成"任意文件上传器"，把凭据变成通用写入通道。上传后是否保留本地由 `--keep` 控制。

### 4.5 压缩器 `usbcomp-r2`

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbcomp-r2.exe pack D:\some\dir -o .\out.usbk --public .\keys\usbbackup-r2.pub.pem
```

源目录 → 流式 zip → 混合加密 → 单一 `.usbk`。源目录全程只读。加 `--keep-plain-zip` 才会额外保留明文 zip（默认不落盘）。

### 4.6 便携工具盘

把工具装到一个 U 盘上，走到哪台机器都能跑：

```PowerShell
# PowerShell（管理员）
..\dist\usbkeygen-r2.exe install-usb `
  --drive I: `
  --subdir backup\tools `
  --keys D:\backup\keys `
  --cred D:\backup\client.json `
  --force
```

盘内布局：

```
I:\
├── .usbbackup-allow        ← 授权标记，必须留在**盘根**
└── backup\tools\
    ├── usbsetup-r2.exe / usbkeygen-r2.exe / usbunseal-r2.exe / usbbackup-r2.exe / usbcomp-r2.exe
    ├── client.exe           内嵌配置与公钥
    ├── client.json          R2 凭据（可选；⚠ DPAPI 只对生成它的那台机器有效）
    ├── keys\usbbackup-r2.pub.pem
    ├── keys\usbbackup-r2.key.pem（默认带；--without-private 可排除）
    └── README.txt
```

**`.usbbackup-allow` 是豁免标记，语义是"别采集我"**：工具盘上放着私钥，一旦被采集打包上传就等于把私钥发布到网上。所以这个标记必须在盘根——豁免判定只在 `<盘根>\.usbbackup-allow` 处 `Stat` 一次，挪进子目录就检测不到，这个盘就会被当成普通介质采集走。

`--without-private` 让私钥不上盘；`--cred` 给了就会顺手打开客户端的上传能力并把凭据一起放进去。

---

## 5. 配置

### 5.1 R2 侧的准备与权限（重要）

**这里有一条必须说清楚的现实**，否则你会按不存在的权限档位去配：

R2 控制台能签发的**长效 API token 只有四档权限**：

| 权限 | 范围 | 能做什么 |
|---|---|---|
| `Admin Read & Write` | 账户级 | 建/删桶、改桶配置、读写所有桶 ❌ **不要用** |
| `Admin Read only` | 账户级 | 列举桶、看桶配置 ❌ **不要用** |
| `Object Read & Write` | **桶级** | 该桶的读、写、列举 ✅ **用这个** |
| `Object Read only` | **桶级** | 该桶的读、列举 |

也就是说：

- **没有"只写不读"这一档**。最小可达权限是 `Object Read & Write`，它同时能读、能覆盖、能删除。
- **可限定的维度是桶，不是 key 前缀**。想真正限定前缀只能用 Temporary Access Credentials（`POST /accounts/{id}/r2/temp-access-credentials`，支持 `prefixes`），但它 **TTL 上限 7 天**，不适合无人值守的常驻客户端。

所以本项目的落地形态是 **`Object Read & Write` + 仅限目标桶**，并配套两件事：

1. **给桶开启版本控制（Object Versioning）**——因为这一档能覆盖和删除，版本控制让"覆盖/误删"不销毁历史版本。**这不是可选项，是前提。**
2. **定期轮换 token**——换一份 `client.json` 就完事，不需要重新编译客户端。

`r2-check` 会用 `ListBuckets` 帮你判断 token 是不是账户级：**能列举桶 = Admin 权限 = 开大了**，报 WARN。

**残余风险，必须知道**：上传凭据泄漏后，持有者不仅能上传伪造对象，还能**读取已有密文、覆盖或删除对象**。前者由端到端加密兜住（没有私钥读不出明文），后者由版本控制兜住。

### 5.2 本项目实际使用的 R2 参数

| 项 | 值 |
|---|---|
| 账户 ID | `aacbb6abba999cde14c3ddcce80ec425` |
| S3 端点 | `https://aacbb6abba999cde14c3ddcce80ec425.r2.cloudflarestorage.com` |
| 桶 | `usbbackup` |
| 对象键前缀 | `usb/` |
| 自定义域 | `usbbackup.immml.top` |
| 签名区域 | `auto`（R2 固定值，不要改） |

对象键形态：`usb/<UTC时间戳>_<净化后的卷标>.zip.usbk`，例如 `usb/20260918T143739Z_OS.zip.usbk`。

把上面这些填成一份 `r2.json`，之后所有 `cred` 命令都可以用 `--from r2.json` 一次带全（`secret_access_key` 留空则仍会交互询问，推荐就这么留）：

```json
{
  "account_id": "aacbb6abba999cde14c3ddcce80ec425",
  "bucket": "usbbackup",
  "endpoint": "https://aacbb6abba999cde14c3ddcce80ec425.r2.cloudflarestorage.com",
  "region": "auto",
  "prefix": "usb/",
  "access_key_id": "<你的 Access Key ID>",
  "secret_access_key": "",
  "label": "office-pc"
}
```

> 注意 `endpoint` **只写协议与主机**，不要带 `/usbbackup` 这段路径——桶名的唯一去处是 `bucket` 字段。带路径会被**明确拒绝**（不是忽略）：S3 客户端按 path-style 自己拼 `/<bucket>/<key>`，端点里的路径会被整段丢掉，于是"我写了桶名"和"实际请求去了哪"从此对不上，而且不会报错。纯粹的尾斜杠（`…com/`）是允许的，与不写路径等价。

> **自定义域 `usbbackup.immml.top` 的用途待确认**：如果把它接成**公开读**的域名，任何人只要知道对象键就能下载密文——内容读不出来（没有私钥），但卷标与时间戳这类元数据会暴露。如果只是给解密器取回用，**不要设成公开**：`usbunseal-r2 pull` 走的是 S3 API 签名请求，不需要公开域名。

### 5.3 配置项

配置文件默认在 `%LOCALAPPDATA%\usbbackup-r2\config.json`。以下是内置默认值的全量导出（`usbbackup-r2 config-check` 会打印生效值）：

```json
{
  "output_dir": "%TEMP%\\backup",
  "public_key_path": "%LOCALAPPDATA%\\usbbackup-r2\\keys\\usbbackup-r2.pub.pem",
  "audit_file": "%LOCALAPPDATA%\\usbbackup-r2\\audit.jsonl",

  "monitor": {
    "poll_interval_sec": 5,
    "debounce_sec": 5,
    "ready_timeout_sec": 10,
    "job_timeout_min": 30,
    "process_mounted_on_start": true,
    "poll_only": false
  },

  "collect": {
    "policy": "all",
    "marker_file": ".usbbackup-collect",
    "exempt_marker_file": ".usbbackup-allow"
  },

  "gate": {
    "used_threshold_bytes": 10737418240,
    "used_threshold": "",
    "max_total_bytes": 10737418240,
    "free_space_margin_percent": 5
  },

  "archive": {
    "store_already_compressed": true,
    "keep_plain_zip": false,
    "excludes": null,
    "threads": 0
  },

  "retention": {
    "keep_per_volume": 5,
    "dedup_enabled": true
  },

  "upload": {
    "enabled": false,
    "credential_file": "%LOCALAPPDATA%\\usbbackup-r2\\client.json",
    "multipart_threshold_bytes": 67108864,
    "part_size_bytes": 67108864,
    "max_retries": 5,
    "upload_timeout_min": 30,
    "delete_local_after_upload": true,
    "keep_local_on_failure": true
  },

  "log": {
    "level": "info",
    "file": "%LOCALAPPDATA%\\usbbackup-r2\\logs\\usbbackup-r2.log",
    "max_size_mb": 10,
    "max_backups": 5,
    "console": true
  }
}
```

两点值得说明：

- `upload.enabled` 默认 **false**：模板程序默认只落本地（行为与不含出站能力的版本一致）。生成器产出的客户端才会显式打开它。
- `upload.credential_file` 默认是 `%LOCALAPPDATA%` 下的绝对路径；**生成器产出的客户端把它设成相对名 `client.json`**，按"与 exe 同目录"解析——这样现场只要把两个文件一起拷过去就行。

### 5.4 两个阈值，别搞混

| 字段 | 含义 | 默认 | 比较对象 |
|---|---|---|---|
| `gate.used_threshold_bytes` | 超过就**不备份** | 10 GiB | 已占用容量 |
| `gate.max_total_bytes` | 超过就**不打包** | 10 GiB（`0` = 不限制） | **待打包数据量（即已占用）**，不是介质容量 |

上限若误比卷总容量，64 GiB 的盘只用了 500 MiB 也会被跳过——正好和意图相反。已有回归测试锁住这一点。

也支持可读写法 `gate.used_threshold = "10GiB"`（或环境变量 `USBBACKUP_R2_USED_THRESHOLD=10GiB`）。

### 5.5 两个标记，语义相反

| 标记 | 位置 | 含义 | 有无它 |
|---|---|---|---|
| `.usbbackup-allow` | **盘根**（只认盘根） | "这块盘是我自己的，别动它" | 有 → **豁免**，任何策略档位下都不采集 |
| `.usbbackup-collect` | **盘根** | "这块盘的内容可以打包上传" | 仅 `marker_only` 档位使用 |

豁免判定**不受策略档位影响**，任何档位都先做这一步。原因很实际：工具盘上放着私钥，一旦被采集上传就等于把私钥发布到网上——这是本项目最不能出的事故，不允许"因为策略是 all 所以跳过豁免检查"这种组合存在。

### 5.6 环境变量

`USBBACKUP_R2_*` 系列可覆盖同名配置项（共 15 个）：

```PowerShell
# PowerShell
$env:USBBACKUP_R2_OUTPUT_DIR          = 'D:\out'
$env:USBBACKUP_R2_PUBLIC_KEY          = 'D:\backup\keys\usbbackup-r2.pub.pem'
$env:USBBACKUP_R2_AUDIT_FILE          = 'D:\backup\audit.jsonl'
$env:USBBACKUP_R2_LOG_LEVEL           = 'debug'
$env:USBBACKUP_R2_COLLECT_POLICY      = 'marker_only'
$env:USBBACKUP_R2_COLLECT_MARKER      = '.usbbackup-collect'
$env:USBBACKUP_R2_COLLECT_EXEMPT_MARKER = '.usbbackup-allow'
$env:USBBACKUP_R2_USED_THRESHOLD      = '10GiB'
$env:USBBACKUP_R2_USED_THRESHOLD_BYTES = '10737418240'
$env:USBBACKUP_R2_MAX_TOTAL_BYTES     = '0'
$env:USBBACKUP_R2_POLL_INTERVAL_SEC   = '5'
$env:USBBACKUP_R2_UPLOAD_ENABLED      = 'true'
$env:USBBACKUP_R2_CREDENTIAL_FILE     = 'D:\backup\client.json'
$env:USBBACKUP_R2_UPLOAD_PART_SIZE    = '67108864'
$env:USBBACKUP_R2_UPLOAD_MAX_RETRIES  = '5'
```

凭据文件口令另有两个变量（**不是**配置项，只在读/写凭据文件时生效）：

```Linux
export USBBACKUP_R2_CRED_PASSPHRASE='...'            # 直接给口令（会出现在 /proc/<pid>/environ 里）
export USBBACKUP_R2_CRED_PASSPHRASE_FILE=~/.config/usbbackup-r2/cred.pass   # 指向"首行为口令"的文件，推荐
```

优先级：显式参数（`--cred-pass-file`）> 口令文件 > `USBBACKUP_R2_CRED_PASSPHRASE` > `USBBACKUP_R2_CRED_PASSPHRASE_FILE`。显式指定永远赢过环境。

**客户端模式（内嵌配置）下上面那 15 个 `USBBACKUP_R2_*` 配置变量全部被忽略**——否则"硬编码配置"就能靠设几个环境变量绕过去。但 `USBBACKUP_R2_CRED_PASSPHRASE*` 这两个**在客户端模式下仍然生效**：它们不是配置，是"怎么解开凭据文件"的输入，客户端照样需要。凭据是 DPAPI 时用不到它们。

### 5.7 审计日志

`audit.jsonl`，一行一条 JSON。字段刻意裁剪过：

```json
{"time":"2026-09-18T22:37:39+08:00","tool":"usbbackup-r2","root":"X:\\","label":"OS",
 "fs":"NTFS","serial":123456789,"total_bytes":0,"used_bytes":0,
 "branch":"archive-encrypt","collect_policy":"all","collected":true,"exempt_marker":false,
 "files":2,"raw_bytes":5019,"cipher_bytes":5216,
 "r2_object_key":"usb/20260918T143739Z_OS.zip.usbk","r2_bucket":"usbbackup",
 "uploaded_bytes":5216,"upload_result":"uploaded","local_product":"deleted",
 "ok":true,"duration_sec":0.07}
```

**没有**文件名、没有文件清单、没有文件内容、没有 token、没有签名头、没有 URL query。有一条针对**结构体定义本身**的回归测试守着这件事——不是对某一条序列化结果做的，因为后者换个用例就绕过去了。

---

## 6. 安全提示

### 不做什么

- **不加壳、不免杀、不隐藏进程/窗口/端口、不写自启动**（服务默认手动启动）。
- **不做 UAC 绕过、不提权、不规避 EDR/杀软**。
- **不引入入站监听、不接受远程指令、没有控制通道、不做内容心跳**。
- **不把 Secret Access Key 编译进 exe**。生成器遇到这种请求直接拒绝并说明理由。
- **私钥检测只做存在性布尔判定**：只看文件名模式与文件头最多 4 KiB 的字节特征，绝不读取、解析、复制、缓存或外传私钥内容；头部缓冲区用后清零。
- **日志与审计不记录私钥的文件名、路径或内容**。

### 出站面

唯一允许的出站目标是配置的 R2 endpoint，仅 HTTPS 且强制证书校验（**没有**跳过校验的开关）。除它之外不发起任何网络调用。容器文件被包装成只有 `PUT` / `HEAD` / `GET` / `DELETE` / `ListObjectsV2` 这几条路径的 S3 客户端，不接受任意 URL 与任意方法。

### 信任边界

| 谁 | 能拿到什么 |
|---|---|
| 客户端所在机器上的**普通用户** | 内嵌公钥 + 加密的凭据文件（读也读不出内容） |
| 客户端所在机器上的**本机管理员/SYSTEM** | 可以以该机器身份解开 DPAPI，从而拿到 R2 凭据 |
| 拿到**口令加密**凭据 + 口令文件的人 | 直接用 R2 凭据（所以口令文件要与凭据分开放） |
| 拿到 `client.exe` 的人 | 只有公钥，**解不开任何密文** |
| 拿到 `.usbk` 密文的人 | 没有私钥就是一堆字节 |
| 拿到私钥的人 | 全部备份 |

**必须承认的事实**：任何落在目标机器上的凭据都存在被提取的可能，尤其是具备本机管理员权限的主体。本项目的防护目标是**把损失面压到最小 + 让轮换成本接近零**，不是声称"不可提取"。轮换的动作是「控制台吊销 token + 在目标机器上重新生成 `client.json`」，**不需要重新编译或重新分发客户端**。

### 三种凭据保护方式，怎么选

| 方式 | 强度 | 跨机器 | 什么时候用 |
|---|---|---|---|
| DPAPI（默认） | 与机器绑定 | ❌ | 客户端跑在生成它的那台 Windows 上 |
| 口令加密 | 取决于口令 | ✅ | 要给 Linux 解密器用，或客户端在另一台机器上 |
| 明文（`--plain-file`） | 只有 0600 权限 | ✅ | 既没有 DPAPI 又无法在启动时提供口令时的最后手段 |

**明文凭据不会自动被读取**：`cred.Load` 要求调用方显式传 `--allow-plain-cred`（解密器）/ `WithAllowPlainFile`（代码）。目的是让"文件忘了加密"变成一个当场可见的错误，而不是一个谁都没注意到的默认行为。

**口令文件不要和凭据放在同一目录**：放在一起，口令文件就只是给加密凭据配了一把"同级的钥匙"，实际强度退回明文。分开放才有意义。

### 部署前的检查清单

- [ ] R2 token 用的是 `Object Read & Write` + 仅限目标桶，**不是** Admin 档
- [ ] 桶已开启**版本控制**
- [ ] `r2-check` 通过（含权限范围检查）
- [ ] `probe --drive <盘符>` 的判定结论符合预期
- [ ] 私钥已离线备份，且**不在**客户端分发的目录里
- [ ] 工具盘上的 `.usbbackup-allow` 在盘根
- [ ] 测试过一次完整的「采集 → 上传 → pull → 解密还原」

---

## 7. 项目结构

```
usbguard-r2/
├── cmd/
│   ├── usbbackup-r2/     主程序 / 客户端（run / once / probe / upload / 服务管理）
│   ├── usbkeygen-r2/     生成器（generate / cred / r2-check / build-client / install-usb）
│   ├── usbsetup-r2/      交互式向导
│   ├── usbunseal-r2/     解密器（init / config / ls / pull / list / verify / unseal）
│   └── usbcomp-r2/       压缩器
├── internal/
│   ├── backup/           流水线编排 + 上传编排 + 保留策略 + 审计
│   ├── collectpolicy/    采集准入判定（豁免标记 + 三档策略）
│   ├── config/           配置加载 / 环境变量 / 校验 / 摘要
│   ├── cred/             凭据保护（DPAPI / 口令加密 / 明文，同一文件格式三种模式）
│   ├── crypto/           混合加密内核（不感知 USB/文件系统语义）
│   ├── r2/               S3 客户端（手写 SigV4、分片上传、重试、下载）
│   ├── archive/          流式 zip / 排除规则 / 解压与 Zip Slip 防护 / 源守卫
│   ├── keystore/         RSA 密钥生成、PEM 读写、口令保护、指纹
│   ├── clientgen/        客户端生成（内嵌配置与公钥）
│   ├── embedcfg/         PE overlay 内嵌配置块（带 SHA-256 校验 + 私钥守卫）
│   ├── agreement/        首次知情同意
│   ├── cli/              参数解析与全局开关重排
│   ├── fsutil/           路径、净化、长路径、原子写
│   ├── logx/             日志
│   ├── version/          版本与产品名
│   ├── winmon/           卷到达事件监控（隐藏顶层窗口 + WM_DEVICECHANGE）
│   ├── winsvc/           Windows 服务控制
│   └── winvol/           卷枚举、容量、门控判定
├── build.ps1 / build.sh
├── README.md / TUTORIAL.md / REQUIREMENTS.md / REQUIREMENTS-R2.md / DISCLAIMER.md
└── dist/                 构建产物
```

依赖方向单向，不成环：

```
cmd/*   →  internal/{backup, cli, config, cred, winsvc, keystore, crypto,
                     archive, r2, embedcfg, clientgen, winmon, winvol, fsutil, logx, version}
backup  →  {collectpolicy, winvol, archive, crypto, config, cred, r2, fsutil, keystore, logx}
archive / r2 / winmon / winvol / keystore / cred / crypto → fsutil, config
```

`internal/crypto` 是纯加密内核，不感知 USB 或文件系统语义。`internal/r2` 只讲 S3 协议，不知道"备份"是什么。`internal/collectpolicy` 单独成包，是因为它承载的是一条**安全语义**（什么情况下允许把一块盘打包上传），只应在一个地方被定义、被验证、被引用。

---

## 8. 开发状态

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M0 | 需求澄清与决策记录 | ✅ |
| M1 | 卷枚举、容量门控、源守卫 | ✅ |
| M2 | 卷到达事件监控（Win32） | ✅ |
| M3 | 流式打包 + 混合加密内核 | ✅ |
| M4 | 密钥管理、配置、命令行、免责声明 | ✅ |
| M5 | 客户端生成与内嵌配置；服务注册 | ✅ |
| M6 | 凭据保护（DPAPI） | ✅ |
| M7 | R2 上传（SigV4 / 分片 / 重试 / 核对） | ✅ |
| M8 | 采集策略、上传编排、解密器拉取 | ✅ |
| M9 | 跨平台凭据（口令加密 / 明文）+ Linux 解密器（`init`/`config`/`ls`/`pull`，amd64 + arm64） | ✅ |

测试：**17 个包有测试，共 218 个用例**。核心路径全在上——容量门控、卷标净化、路径守卫与 Zip Slip、加解密往返、篡改/截断/错误密钥拒绝、SigV4 官方已知答案向量、假 S3 端到端（含分片与 Abort）、采集策略与豁免、上传编排与本地去留矩阵、内嵌配置往返与私钥守卫、凭据三种保护方式（DPAPI / 口令 / 明文）的往返与拒绝路径、配置文件的按键合并。

### 8.1 两处独立交叉验证

上传这条链路最容易"看起来对、其实错"，所以关键环节做了双重独立验证：

1. **SigV4 签名**：用 AWS 官方已知答案向量锁死（`get-vanilla` → `5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31`、`get-vanilla-query-order-key-case` → `b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500`），并用独立的 Python（`hmac` + `hashlib`）实现复算交叉核对。
2. **假 S3 服务端**：自带**独立实现**的规范请求拼装与 HMAC 计算（不复用被测代码），每收到一个请求都会复算签名与 `x-amz-content-sha256` 并比对。这样能抓出被测实现里的转义或排序错误。

### 8.2 本机没有可移动介质时的验证手段

- `subst X: <目录>` + `--allow-fixed` 造出一块可写的固定卷（端到端测试就是这么跑的）；
- `--simulate-arrival X:` 注入一次模拟的卷到达事件，跑通"监控 → 队列 → 流水线"的完整链路。

两条都只用于验证与排障，生产环境不要开启。

### 8.3 由"跑一遍"发现并修复的缺陷

单测没有发现、实际跑起来才暴露的问题（这类问题在本项目里出现过 8 次）：

1. `WM_DEVICECHANGE` 的接收窗口不能是 `HWND_MESSAGE`——消息专用窗口收不到广播，必须建一个隐藏的顶层窗口（`WS_POPUP`，不设 `WS_VISIBLE`）。
2. `RegisterDeviceNotificationW` **不支持** `DBT_DEVTYP_VOLUME`（返回 `ERROR_INVALID_DATA`），卷到达只能靠默认广播。
3. Go 结构体因对齐会补齐，**不能用 `unsafe.Sizeof` 填 C 侧 size 字段**（`DEV_BROADCAST_VOLUME` 固定 18 字节）。
4. Go 的 `URL.EscapedPath()` 不会转义 `+ : = @ & $ , ;`，而 SigV4 要求全部百分号编码——直接用会让含这些字符的对象键被拒签。
5. `url.Values.Encode()` 把空格编成 `+`，SigV4 要求 `%20`——查询串必须手写编码。
6. 分片上传失败时若不用 `context.WithoutCancel` 发 `AbortMultipartUpload`，`ctx` 已取消会导致 abort 也失败，远端留下**计费的**残留分片。
7. `sc.exe` 的输出是本地化的（中文系统是 GBK），直接转述会乱码——要翻译退出码并只取 ASCII 行。
8. `objectURL` 会整体覆盖 URL 的 `Path`（path-style 只能由 `bucket` + `key` 拼出），所以**端点里带的路径会被静默丢弃**：写成 `https://<acct>.r2.cloudflarestorage.com/usbbackup` 照样"跑通"，只是请求打到了 `/<bucket>/…` 而不是你写的那段路径。发现方式是拿假 S3 打印实际收到的 `bucket` / `key`，看到路径被吞掉。修法是在 `cred.ValidateEndpoint` 里**拒绝**带路径的端点（而不是继续忽略），并把校验提到"询问 Secret 之前"。

### 8.4 与 `UsbBackUP` 的独立化说明

本仓库从 `UsbBackUP` 派生，但**不共享代码**。派生时做的主要改动：

- 新增 `internal/r2`（手写 S3 客户端）与 `internal/cred`（凭据保护，Win 上 DPAPI、Linux 上口令加密）；
- 新增 `internal/collectpolicy`（替代原来的私钥存在性检测分支判定）；
- **移除** `internal/keyfile` 与 `internal/copier`（私钥检测与回写分支）；
- `internal/backup` 的流水线由"双分支"改成"单一采集链路 + 可选上传"，新增 `upload.go`；
- `internal/clientgen` 去掉回写源目录，加入上传开关与凭据名（`UploadEnabled` / `CredentialFile`）。

---

## 9. 许可

见 `LICENSE`。

---

## 10. 免责声明

**使用前请完整阅读 `DISCLAIMER.md`**。首次运行任一程序时会要求输入 `I AGREE` 确认。

要点：

- 本工具会**读取被采集介质的全部内容**并上传到你配置的对象存储。**只在你拥有或已获得明确授权的设备与介质上使用。**
- 加密强度取决于你的密钥管理。**私钥丢失 = 备份不可恢复**，本项目不提供任何后门或恢复途径。
- 上传凭据由你自行在云侧创建与授权，权限配置不当造成的后果由你承担。
- 作者不对数据丢失、凭据泄漏、误用或任何间接损失负责。
