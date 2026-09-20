# usbbackup-r2 使用教程

从零开始走一遍：**生成密钥 → 生成 R2 凭据 → 产出客户端 → 部署 → 取回 → 还原**。

> ⚠️ 开工前请先读 [DISCLAIMER.md](DISCLAIMER.md)。本工具仅限用于你本人自有、
> 或已获得明确书面授权的设备与存储介质。

本教程里的命令都标了 Shell 环境。**PowerShell** 的续行符是反引号 `` ` ``，**CMD** 是 `^`，别混用。

---

## 0. 先搞清楚三件事

### 三个角色

| 角色 | 程序 | 在哪跑 | 手里有什么 |
|---|---|---|---|
| **生成器** | `usbkeygen-r2.exe` | 你的机器 | 生成密钥对与 R2 凭据；**私钥留在你这里** |
| **客户端** | 生成器产出的 `client.exe` | 目标机器 | 只有**公钥 + 配置**（内嵌在 exe 里）+ 上传凭据 |
| **解密器** | `usbunseal-r2.exe`（Linux 用 `usbunseal-r2-linux-*`） | 你的机器 / 任意 Linux | 用**私钥**从 R2 拉取并解密还原 |

客户端**没有私钥**——即使整个 exe 被拷走，也解不开它自己产出的文件。

### 插入 U 盘后会发生什么

```
插入 U 盘
   │
   ├─► 卷还没就绪？等一会儿（最多 ready_timeout_sec）
   │
   ├─► 不是可移动卷？──► 跳过
   │
   ├─► 盘根有 .usbbackup-allow ？──► 有 → **豁免**，什么都不做
   │                                  （自己的工具盘走这条，防止私钥被传上网）
   │
   ├─► 采集策略
   │     all          → 放行
   │     marker_only  → 盘根有 .usbbackup-collect 才放行
   │     off          → 跳过
   │
   └─► 放行后看容量：已占用 > 阈值？
          ├─ 是 ──► 跳过，什么都不做
          └─ 否 ──► 整盘打包 + 混合加密（明文 zip 不落盘）
                     ├─► 上传到 R2（若已开启）
                     ├─► HEAD 核对远端大小
                     └─► 按配置删/留本地密文
```

**全程不会删除、移动、改写源介质上的任何文件**，对源盘只读。

### 阈值与上限（容易混淆）

| 字段 | 含义 | 默认 | 比的是 |
|---|---|---|---|
| `used_threshold` | 超过就**不备份** | 10 GiB | 卷的已占用容量 |
| `max_total_bytes` | 超过就**不打包** | 10 GiB（`0`=不限制） | 待打包的数据量（同样是已占用） |

单位可以写清楚：`10GiB`（二进制，Windows 口径）/ `10GB`（十进制，厂标口径）/ `1.5TiB`。

---

## 1. 准备

### 目录

下面假设你在 `D:\backup` 下干活（放密钥与凭据），构建产物在 `D:\...\usbguard-r2\dist`。

```PowerShell
# PowerShell
mkdir D:\backup -Force
cd D:\backup
```

### 不想记参数：用交互式向导

```PowerShell
# PowerShell
..\dist\usbsetup-r2.exe
```

双击即进入黑窗口，一问一答走完（密钥 → 产物目录 → 阈值 → 打包上限 → 采集策略 → 上传 → 输出），每步直接回车就采用方括号里的默认值。适合偶尔用一次、或不熟悉参数的情况。

### 先做一次 R2 侧的准备工作

到 Cloudflare 控制台：

1. 建一个桶（本项目的配置用 `usbbackup`）。
2. **给桶打开版本控制**（Object Versioning）——这是配套前提，理由见下面 §1.1。
3. `Manage R2 API Tokens` → `Create API Token`：
   - Permissions 选 **`Object Read & Write`**（**不要**选 Admin 两档）
   - 勾上 `Apply to specific buckets only`，只勾目标桶
   - 记下 `Access Key ID` 与 `Secret Access Key`（密钥只显示一次）

### 1.1 R2 权限的现实（必须知道，否则会按不存在的档位去配）

R2 控制台能签发的**长效 token 只有四档**：

| 权限 | 范围 | 能做什么 |
|---|---|---|
| `Admin Read & Write` | 账户级 | 建/删桶、改桶配置、读写所有桶 ❌ 不要用 |
| `Admin Read only` | 账户级 | 列举桶、看桶配置 ❌ 不要用 |
| `Object Read & Write` | **桶级** | 该桶的读、写、列举 ✅ 用这个 |
| `Object Read only` | **桶级** | 该桶的读、列举 |

也就是说：

- **没有"只写不读"这一档**。最小可达权限是 `Object Read & Write`，它同时能读、能覆盖、能删除。
- **可限定的是桶，不是 key 前缀**。要真正限定前缀只能用 Temporary Access Credentials（支持 `prefixes`），但它 **TTL 上限 7 天**，不适合无人值守的常驻客户端。

所以必须配套两件事：

1. **桶开版本控制**——这一档能覆盖和删除，版本控制让"覆盖/误删"不销毁历史版本。**不是可选项。**
2. **定期轮换 token**——换一份 `client.json` 就完事，不必重新编译客户端。

别指望"凭据就算被拿到也没关系"：泄漏的凭据能读、能覆盖、能删除。加密只保护**内容**（没有私钥读不出明文），保护不了**可用性**——可用性靠版本控制。

---

## 2. 第一步：生成密钥对（你的机器）

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbkeygen-r2.exe generate --out .\keys --pass
```

- `--bits 4096` 是默认值（下限 2048，上限 8192）。
- `--pass` 会交互式要口令（无回显）。**不要**用 `--pass-file` 把口令写进文件后忘了删。
- 想脚本化：`--pass-file .\pass.txt`，用完立刻删掉那个文件。

产物：

```
D:\backup\keys\
├── usbbackup-r2.pub.pem    ← 公钥，会内嵌进客户端
└── usbbackup-r2.key.pem    ← 私钥，带口令保护，**绝不外传**
```

立刻验一下：

```PowerShell
# PowerShell
..\dist\usbkeygen-r2.exe inspect .\keys\usbbackup-r2.pub.pem
```

会打印位数与指纹。**记下指纹**——它在解密时也会显示，便于确认"这份密文是给哪把钥匙的"。

> **私钥丢了就永远解不开。** 现在就去离线备份 `keys\` 目录与口令。
> 本工具没有任何后门或恢复途径，这是设计而非缺陷。

---

## 3. 第二步：生成 R2 凭据（你的机器）

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbkeygen-r2.exe cred `
  --out .\client.json `
  --account-id aacbb6abba999cde14c3ddcce80ec425 `
  --bucket usbbackup `
  --prefix usb/ `
  --access-key-id <你的 Access Key ID> `
  --label "office-pc 上传凭据"
```

`Secret Access Key` **会交互式询问**（无回显），不要用 `--secret-access-key` 写在命令行上——那会留在 shell 历史与进程命令行里（`wmic process` 就能看到）。

生成完立刻探活：

```PowerShell
# PowerShell
..\dist\usbkeygen-r2.exe r2-check --cred-file .\client.json
```

预期输出（示意）：

```
凭据文件  : D:\backup\client.json
  端点        : https://<账户>.r2.cloudflarestorage.com
  桶          : usbbackup
  前缀        : usb/
  用途        : 上传
  凭据        : AKID…

检查项：
  [OK  ] 写入对象（Object Write） 已写入 usb/probe-3f9a1c.txt（ETag …）
  [OK  ] 读回对象元数据（HeadObject） 大小 58 字节一致
  [OK  ] 权限范围（ListBuckets） 已被拒绝，说明不是账户级 Admin 权限
  [OK  ] 清理探活对象 已删除（不留垃圾）

全部检查通过：端点可达、签名被接受、该前缀下可写。
```

如果 `权限范围（ListBuckets）` 是 **[WARN]**，说明 token 是 Admin 档——**换掉它**，回到 §1.1 重选 `Object Read & Write`。

### 关于凭据保护的三个提醒

`client.json` 里的 Secret 有三种保护方式，由生成时的开关决定（都不给则按平台默认）：

| 开关 | 保护方式 | 跨机器 |
|---|---|---|
| （默认） | Windows DPAPI **机器范围** | ❌ 只在生成它的那台 Windows 上能解 |
| `--cred-pass-file <口令文件>` / `--cred-pass` | 口令加密（PBKDF2-SHA256 + AES-256-GCM） | ✅ 任何平台都能读 |
| `--plain-file` | 明文（只有 0600 权限） | ✅ 但等于没加密 |

所以：

- 在这一台电脑上生成的 DPAPI 凭据，拿到**别的电脑上解不开**（报"凭据解密失败"）。这是设计意图，不是故障。
- **部署到哪台机器，就在哪台机器上生成一份。** 便携工具盘上的 `client.json` 也一样——换了机器就要重新生成。
- 换机/重装系统后重新执行一次 `usbkeygen-r2 cred` 即可。
- **要拿去 Linux 上用的那一份必须用口令加密**（Linux 没有 DPAPI）：

  ```PowerShell
  # PowerShell（你的机器）—— 口令放文件里，不要写在命令行上
  cd D:\backup
  'my-cred-passphrase' | Out-File -Encoding ascii -NoNewline .\cred.pass
  ..\dist\usbkeygen-r2.exe cred --out .\client-linux.json --from .\r2.json --cred-pass-file .\cred.pass
  ```

- 同一条 R2 token 可以生成多份凭据，保护方式各选各的：客户端那份 DPAPI、解密器那份口令，互不冲突。
- 泄漏的处置是**控制台吊销 token + 重新生成 `client.json`**，不需要重新编译客户端。

---

## 4. 第三步：产出客户端（你的机器）

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbkeygen-r2.exe build-client `
  --public .\keys\usbbackup-r2.pub.pem `
  -o .\client.exe `
  --template ..\dist\usbbackup-r2.exe `
  --output-dir "%TEMP%\backup" `
  --threshold 10GiB `
  --max-total 10GiB `
  --collect all `
  --name "office-pc" `
  --upload `
  --cred-name client.json
```

要点：

| 参数 | 作用 |
|---|---|
| `--public` | 公钥 PEM。**只能传公钥**，误传私钥会被直接拒绝 |
| `-o` | 客户端输出路径 |
| `--template` | 客户端模板（同目录的 `usbbackup-r2.exe`） |
| `--output-dir` | 密文产物在本机的落盘目录，支持 `%TEMP%` 这类变量 |
| `--threshold` | 容量门控阈值 |
| `--max-total` | 打包体积上限（`0` = 不限制） |
| `--collect` | 采集策略：`all` / `marker_only` / `off` |
| `--upload` | 打开上传能力（不给就只落本地） |
| `--no-upload` | 显式关掉上传 |
| `--cred-name` | 内嵌的凭据文件名（相对名，客户端按"与自身同目录"解析） |

产物是**单个 exe**：配置与公钥以 PE overlay 块的形式追加在文件尾部，带 SHA-256 校验。块损坏时报错并退回常规路径，**不会静默使用来源不明的配置**。

客户端模式**忽略**外部 `config.json` 与环境变量——否则"硬编码配置"就能靠改配置绕过去。

校验一下内嵌内容真的进去了（客户端会打印**内嵌生效值**）：

```PowerShell
# PowerShell
cd D:\backup
.\client.exe config-check
```

输出里配置来源会显示 `<内嵌于可执行文件>`，并列出产物目录、阈值、采集策略、上传开关等生效值。如果它反而去读了 `%LOCALAPPDATA%\usbbackup-r2\config.json`，说明内嵌块没写进去——重新生成一次。

> 更省事的办法：用向导 `usbsetup-r2.exe`，它会问同样几个问题然后调用同一份生成逻辑。

---

## 5. 第四步：部署到目标机器

把 **`client.exe` 和 `client.json` 放在同一个目录**（客户端按"与 exe 同目录"找凭据）：

```PowerShell
# PowerShell（在你的机器上打包带走）
mkdir D:\deploy -Force
copy .\client.exe D:\deploy\
copy .\client.json D:\deploy\
```

拷到目标机器（U 盘、共享目录、远程复制都行），然后：

### 5.1 首次确认（一次即可）

```CMD
REM 目标机器 · CMD（管理员）
cd C:\backup-agent
client.exe accept --yes
```

`accept` 会展示完整的安全警告并要求 `I AGREE`。`--yes` 用于自动化部署（打印简短提示后确认）。**服务模式下会跳过这个交互**——否则 SCM 拉起进程后会立即退出并报 1053。

查看当前状态：

```CMD
client.exe accept --check
```

未确认时退出码是 `2`。撤销确认用 `accept --revoke`。

### 5.2 先诊断，别急着跑

```CMD
REM 目标机器 · CMD
cd C:\backup-agent
client.exe probe --drive E:
```

`probe` **只读**：不写数据、不发网络请求。它会告诉你这个盘会被怎么处理：

- 盘根有没有授权标记（有没有被豁免）
- 采集策略会不会放行
- 容量有没有超阈值
- 最终会走"打包 + 加密 + 上传"还是"跳过"
- 上传通道是否可用（凭据能否在本机解开）

**这一步跑通再往下走**，能省掉大量来回排查。

### 5.3 运行

```CMD
REM 目标机器 · CMD
client.exe run
```

前台常驻：事件驱动为主（`WM_DEVICECHANGE`），轮询兜底。插盘就干，不插盘就等着。

只想处理当前已经插着的盘：

```CMD
REM 目标机器 · CMD
client.exe once --drive E:
```

### 5.4 装成服务（可选，需管理员）

```CMD
REM 目标机器 · CMD（管理员）
cd C:\backup-agent
client.exe install-service
client.exe start
client.exe status
```

- 服务默认**手动启动**，不写自启动（本项目不加壳、不隐藏、不做任何规避动作）。
- **服务模式下 `%LOCALAPPDATA%` 指向系统配置目录**，不是用户目录。所以部署时一律用绝对路径，别依赖环境变量展开。
- **`install-service` 把 `binPath` 钉在你执行它的那个 `client.exe` 上**（`os.Executable()`）。
  所以上面那个 `cd C:\backup-agent` 不是装饰——**先在本地目录装，别在 U 盘上装**：
  在盘上装会让服务绑死盘符，拔盘即失效，凭据也会跟着解析到盘上那份。
  U 盘只当分发介质。

排障时前台跑更容易看到日志：

```CMD
REM 目标机器 · CMD
client.exe run --poll-only
```

`--poll-only` 强制只用轮询，用于排除事件驱动的问题。

---

## 6. 第五步：取回并解密（你的机器）

解密器是 **git 风格**的：`init` 写配置、`config` 看配置、`ls` 列远端、`pull` 取回并解密。配置默认在 `%AppData%\usbbackup-r2\unseal.json`。

```PowerShell
# PowerShell（放着私钥的那台机器）
cd D:\backup
..\dist\usbunseal-r2.exe init `
  --cred .\client.json `
  --key .\keys\usbbackup-r2.key.pem `
  --out-dir D:\restore
```

`init` 只写**路径与开关**，不保存任何凭据或私钥内容。它会顺手检查两件最容易漏的事：凭据是口令加密但没填口令文件、私钥带口令但没填口令文件——这两种配置跑起来必然失败。

### 先确认配置，再看远端有什么

```PowerShell
# PowerShell
..\dist\usbunseal-r2.exe config      # 生效配置 + 关键文件是否存在 + 凭据保护方式
..\dist\usbunseal-r2.exe ls          # 相当于 git ls-remote
```

`ls` 的预期输出：

```
凭据      : D:\backup\client.json（https://…r2.cloudflarestorage.com / usbbackup ，用途 upload）
前缀      : usb/
对象数    : 3（合计 24.1 MiB）

  -    8.0 MiB  usb/20260918T143739Z_OS.zip.usbk
  -    8.1 MiB  usb/20260917T011204Z_OS.zip.usbk
```

（`-` 那列是需要额外请求才知道的元数据，`ls` 刻意不去逐个探测——列一次远端不该产生 N 次请求。）

> **上传用的凭据通常没有读权限？** 在本项目里它有——因为 R2 的最小档位就是 `Object Read & Write`（见 §1.1）。如果列举被拒，说明 token 权限范围没覆盖这个桶。

### 下载 + 解密 + 解压（一条命令）

```PowerShell
# PowerShell
..\dist\usbunseal-r2.exe pull --pass
```

配置里已经有 `out_dir` / `key_file`，所以不必再写一遍。默认只取**最新一个**对象（对应"我刚插过一次盘"这个最常见的场景）。流程：

```
列举 → 选中最新对象 → 下载到临时目录
  → 校验容器头（确认是给这把密钥的密文）
  → 解密到临时 zip
  → 解压到 <out_dir>\<对象名>\（Zip Slip 防护生效）
  → 删临时文件
```

常用开关：

| 开关 | 作用 |
|---|---|
| `--all` | 取回前缀下的**全部**对象（补历史） |
| `--object <键>` | 只处理指定的对象键（也可直接当位置参数写） |
| `--skip-existing` | 目标目录已存在就跳过（默认开，重跑幂等） |
| `--force` | 目标目录已存在时覆盖 |
| `--keep-container` | 保留下载下来的 `.usbk` 密文 |
| `--delete-remote` | 解密成功后删远端对象（**默认不动远端**） |
| `--dry-run` | 只显示将要做什么，不下载不写盘 |
| `--pass-file` / `--pass` | 私钥口令：从文件读 / 交互输入 |
| `--config <路径>` | 用指定的配置文件（默认 `%AppData%\usbbackup-r2\unseal.json`） |

### 6.1 在 Linux 上取回（树莓派 / NAS / 服务器）

解密器有 `linux/amd64` 与 `linux/arm64` 两个**原生产物**（`./build.sh linux` 产出）。取回备份的人通常不在生成备份的那台 Windows 前，所以这条路径是正经支持的一条，不是"凑合能跑"。

Linux 上没有 DPAPI，所以有一条硬约束：

> **DPAPI 保护的 `client.json` 在 Linux 上读不了**，会明确报"该凭据文件由 Windows DPAPI 保护……只能在 Windows 上读取"。
> 要在 Linux 上用，凭据必须用 `--cred-pass-file` 生成（见 §3）。

```Linux
# Linux
mkdir -p ~/.config/usbbackup-r2 && cd ~/.config/usbbackup-r2
# 从 Windows 拷过来：client-linux.json、cred.pass、usbbackup-r2.key.pem、key.pass、
# 以及 usbunseal-r2-linux-amd64（或 -arm64）。
# Windows 上产出的文件没有可执行位，且 ls 在 NTFS 上不会显示它——记得补一次：
chmod +x usbunseal-r2-linux-amd64
chmod 600 cred.pass key.pass client-linux.json

./usbunseal-r2-linux-amd64 init \
  --cred ~/.config/usbbackup-r2/client-linux.json \
  --cred-pass ~/.config/usbbackup-r2/cred.pass \
  --key ~/.config/usbbackup-r2/usbbackup-r2.key.pem \
  --key-pass ~/.config/usbbackup-r2/key.pass \
  --out-dir ~/usb-restore

./usbunseal-r2-linux-amd64 config     # 先看清生效配置与凭据保护方式
./usbunseal-r2-linux-amd64 ls         # 列远端
./usbunseal-r2-linux-amd64 pull       # 取最新一个并解密解压
```

口令的其它来源（适合 systemd 单元 / 定时脚本）：环境变量 `USBBACKUP_R2_CRED_PASSPHRASE` 或 `USBBACKUP_R2_CRED_PASSPHRASE_FILE`。两者都**不如口令文件**——`/proc/<pid>/environ` 对同机同用户与 root 可读，`ps eww` 也可能带出来。单用户机器能接受，多用户机器请用 `cred_pass_file`。

**口令文件不要和凭据放同一个目录**：放一起等于给加密凭据配了把同级的钥匙，强度退回明文。

### 只想解本地文件

不经过 R2 也行：

```PowerShell
# PowerShell
..\dist\usbunseal-r2.exe list .\some.usbk                              # 只看容器头，不需要私钥
..\dist\usbunseal-r2.exe verify .\some.usbk --key .\keys\usbbackup-r2.key.pem --pass
..\dist\usbunseal-r2.exe unseal .\some.usbk -d D:\restore --key .\keys\usbbackup-r2.key.pem --pass
```

---

## 7. 进阶：手工补传

客户端上传失败时会保留本地产物（默认 `keep_local_on_failure: true`），日志和审计里都有对象键。事后补传：

```PowerShell
# PowerShell（目标机器上）
cd C:\backup-agent
client.exe upload "%TEMP%\backup\E_OS.zip.usbk"
```

`upload` 只接受本工具产出的 `.usbk`（会校验容器魔数）——免得它被当成"任意文件上传器"，把凭据变成通用写入通道。

- 默认按 `{前缀}{UTC时间戳}_{文件名}` 生成对象键；要指定就用 `--key`。
- 默认**上传成功后删掉本地产物**（`delete_local_after_upload`），加 `--keep` 保留。

---

## 8. 进阶：不生成客户端，本机直接用

如果就是在这台机器上用，不折腾内嵌：

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbkeygen-r2.exe use .\keys\usbbackup-r2.pub.pem      # 登记公钥到配置
# 需要上传就编辑 %LOCALAPPDATA%\usbbackup-r2\config.json 把 upload.enabled 改成 true
..\dist\usbbackup-r2.exe config-check
..\dist\usbbackup-r2.exe run
```

配置里值得改的几项：

```json
{
  "collect": { "policy": "marker_only" },
  "gate":    { "used_threshold": "20GiB", "max_total_bytes": "10GiB" },
  "upload":  { "enabled": true, "credential_file": "D:\\backup\\client.json" }
}
```

- `collect.policy = marker_only` 更保守：只有盘根带 `.usbbackup-collect` 的盘才采集，其余零读取跳过。
- `upload.credential_file` 写**绝对路径**最省事（本机模式下没有"与 exe 同目录"的语义约束）。

---

## 9. 组装一个便携工具 U 盘

```PowerShell
# PowerShell
cd D:\backup
..\dist\usbkeygen-r2.exe install-usb `
  --drive I: `
  --subdir backup\tools `
  --keys D:\backup\keys `
  --cred D:\backup\client.json `
  --threshold 10GiB `
  --max-total 10GiB `
  --collect all `
  --force
```

`--threshold` / `--max-total` / `--collect` 是**写进盘内 client.exe 的内嵌配置**。装盘时若工具目录里已有一份现成的 `client.exe`，命令会**报错**而不是忽略这几个开关——它改不动已经定死的内嵌块，而静默忽略会让你以为阈值改了、实际盘上跑的仍是旧的。

会写进盘里：

```
I:\
├── .usbbackup-allow                 ← 授权标记（必须留在盘根）
└── backup\tools\
    ├── usbsetup-r2.exe / usbkeygen-r2.exe / usbunseal-r2.exe / usbbackup-r2.exe / usbcomp-r2.exe
    ├── client.exe
    ├── client.json                  ← --cred 给了才有
    ├── keys\usbbackup-r2.pub.pem
    ├── keys\usbbackup-r2.key.pem    ← --without-private 可排除
    └── README.txt
```

### 为什么这个盘不会被采集走

盘根有 `.usbbackup-allow`。客户端读到它就知道"这是自己人的盘，里面甚至有私钥"，于是**豁免**：不读取、不打包、不上传。这条判定**不受采集策略影响**——哪怕策略是 `all` 也一样豁免。

**别把 `.usbbackup-allow` 挪进子目录。** 豁免判定只在 `<盘根>\.usbbackup-allow` 处 `Stat` 一次；挪走就检测不到，这个带着私钥的盘就会被当成普通介质打包上传。

**这个文件名与项目 A（不含出站能力的版本）共用。** 装盘时只**追加**指纹、绝不覆盖：A 的判定是逐行比对指纹的，盘根可能已经有 A 写的那行；覆盖会让 A 认不出这块盘，于是 A 把它当普通介质扫描打包——而这块盘里有私钥。所以 `install-usb` 是追加 + 幂等的，重复装盘不会覆盖也不会失败，装完输出里会写明走了哪条分支（新建 / 追加 / 已含相同指纹）。

### 盘内 client.json 是哪种凭据，决定怎么部署

| 保护方式 | 盘插到别的 Windows 机器上 |
|---|---|
| 口令加密（`--cred-pass-file` 生成） | **能直接用**，但要给客户端口令 |
| DPAPI（默认生成） | **不能用**，必须在目标机器上重新 `usbkeygen-r2 cred` 一份 |

口令加密那份最容易踩的坑：**漏给口令不会报错，只是上传被跳过、产物全留在本地**，现场表现是"跑了半天，R2 上什么都没有"。

```PowerShell
# PowerShell（目标机器上）
# 客户端只认这两个环境变量，它**没有** --cred-pass-file 开关
setx USBBACKUP_R2_CRED_PASSPHRASE_FILE "C:\ProgramData\usbbackup-r2\cred.pass"
I:\backup\tools\client.exe cred-check        # 立刻验证：应列出端点/桶/前缀

# 注册成服务的话，服务以 LocalSystem 运行，用户级变量它看不见
setx /M USBBACKUP_R2_CRED_PASSPHRASE_FILE "C:\ProgramData\usbbackup-r2\cred.pass"
```

口令文件本身要放在**盘外**、权限收紧，也不要与客户端同目录。

### 盘上放不放私钥

| 做法 | 后果 |
|---|---|
| 默认（带私钥） | 盘丢 = 所有用对应公钥加密的备份都能被解开。私钥带口令时还要考虑口令是否也在同一处 |
| `--without-private` | 盘上只有公钥。解密时要回你的电脑取私钥，稍麻烦但安全得多 |

安装完会打印一行风险提示，并如实区分"明文私钥"与"带口令的私钥"——README.txt 里也按真实类型写，不会一律写成明文。

---

## 10. 排障

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 用法错误（参数写错） |
| 2 | 未同意免责声明（先跑 `accept`） |
| 3 | 功能未实现 |
| 4 | 运行期错误 |
| 5 | 部分成功（例如多个对象里有几个处理失败） |

### 日志

- 前台运行时日志打到 stderr。
- 服务模式写到 `%LOCALAPPDATA%\usbbackup-r2\logs\usbbackup-r2.log`（轮转：单文件 10 MB，保留 5 份）。
- 审计在 `%LOCALAPPDATA%\usbbackup-r2\audit.jsonl`，一行一条 JSON。

### 常见问题

| 现象 | 原因与处置 |
|---|---|
| `凭据解密失败（文件已损坏、被篡改，或不是在本机生成的）` | `client.json` 来自别的机器。DPAPI 是机器范围的，**在目标机器上重新生成** |
| `该凭据文件由 Windows DPAPI 保护……只能在 Windows 上读取（当前不是 Windows）` | 拿 DPAPI 凭据去 Linux 用了。用 `usbkeygen-r2 cred --cred-pass-file <口令文件>` 重新生成一份口令加密的（见 §3） |
| `该凭据文件由口令保护，需要提供口令` / `口令不正确（或凭据文件已被篡改）` | 凭据是口令加密的：前者是没给口令，给 `--cred-pass-file` 或设 `USBBACKUP_R2_CRED_PASSPHRASE*`；后者是口令错或文件被动过，口令没有找回途径 |
| `该凭据文件未加密（仅靠文件权限保护），读取它需要显式开启 --allow-plain-cred` | 明文档必须显式放行。确认是有意为之，否则重新生成一份加密的 |
| `明文凭据文件权限过宽（要求 0600）` | `chmod 600` 该文件（Windows 上不检查权限位） |
| `未找到凭据文件 client.json；已查找：…` | 报错里会列出**全部**候选路径。现场最常见的是"只拷了 exe 没拷 client.json" |
| 日志里有 `上传已禁用：凭据不可用，本次仅保留本地产物` | 凭据不可用，但作业本身成功、密文留在了本地。按日志里的原因处理后用 `upload` 补传 |
| 上传报 `AccessDenied` | token 的权限范围没覆盖这个桶，或选错了档位。回到 §1.1 |
| 上传报 `SignatureDoesNotMatch` | Secret 抄错了，或**本机时间与标准时间偏差过大**（SigV4 对时钟敏感） |
| 远端对象大小与本地不一致 | 传输链路有问题。工具会自动重传一次；仍不符则标记失败并保留本地 |
| 盘插上没反应 | 先用 `probe --drive E:` 看判定；若事件不触发，`run --poll-only` 用轮询兜底 |
| 作业直接跳过、日志写 `exempt-marker` | 盘根有 `.usbbackup-allow`，被豁免了。这是期望行为 |
| 作业跳过、原因是 `no-collect-marker` | 策略是 `marker_only`，而盘根没有 `.usbbackup-collect` |
| 作业跳过、原因是 `used-over-threshold` | 已占用容量超阈值。调大 `used_threshold` 或换盘 |
| 作业跳过、原因是 `max-total-exceeded` | 待打包数据量超 `max_total_bytes`。调大它或设成 `0`（不限制）。**注意它比的是数据量，不是介质容量** |
| 服务启动报 1053 | 服务模式下必须跳过 `I AGREE` 交互确认，先跑一次 `accept`，再看日志 |

### 想看清楚发生了什么

```PowerShell
# PowerShell
$env:USBBACKUP_R2_LOG_LEVEL = 'debug'
..\dist\usbbackup-r2.exe run
```

注意客户端模式下环境变量被忽略；要调客户端的日志级别，得在 `build-client` 时用 `--config` 指定基础配置。

---

## 11. 安全检查清单

部署前逐条过一遍：

- [ ] R2 token 是 `Object Read & Write` + **仅限目标桶**，不是 Admin 档
- [ ] 桶已开启**版本控制**（2026-09-20 实测 `usbbackup` 桶**未开启**；README §5.2.3 有查法）
- [ ] `r2-check` 全部 `[OK]`（`列表(权限范围)` 那一项不能是 WARN）
- [ ] 私钥有离线备份，口令不在同一处
- [ ] `client.exe` 与 `client.json` 一起部署，且**不包含私钥**
- [ ] `probe --drive <盘符>` 的结论符合预期
- [ ] 工具盘的 `.usbbackup-allow` 在**盘根**
- [ ] 完整跑通过一次「采集 → 上传 → pull → 解密还原」
- [ ] 知道自己能接受什么：客户端所在机器的**管理员**能提取 R2 凭据

---

## 12. 一图流

```
你的机器                                目标机器                       你的机器
────────                                ────────                       ────────
generate ──► keys\pub.pem  ─┐
             keys\key.pem ──┼──► 保管好
                            │
cred ──► client.json ───────┤
                            │
build-client ──► client.exe ┤（内嵌公钥+配置）
                            │
                            └──► 两个文件拷过去 ──► accept ──► run
                                                      │
                                                      ├─ 插盘
                                                      ├─ 豁免/策略/容量判定
                                                      ├─ 打包 → 加密 → .usbk
                                                      └─ 上传 ──► R2 桶
                                                                    │
                                                    usbunseal-r2 pull ──┘
                                                      （你机器上的私钥解密）
```

私钥从头到尾没有离开过你的机器。
