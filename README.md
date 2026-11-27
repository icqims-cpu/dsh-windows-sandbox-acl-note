# Windows 上 DSH 沙箱写不进去：先分清「策略拒绝」「DACL 拒绝」「完整性标签拒绝」

> 读者：在 Windows 上运行 DeepSeek Harness（下称 DSH），遇到工作区写入、目录列举、临时目录创建失败的人。
>
> 覆盖的报错：`[sandbox: file access denied under workspace-write mode]`（read-only 模式下括号里是 `read-only`）、`拒绝访问` / `Access is denied`、`UnauthorizedAccessException`、`PermissionError: [WinError 5]`。
>
> 读完应当能做到：十分钟内判定失败发生在哪一层，用对应命令修好，并且知道下一次怎么避免。

## 0. 先记住三句话

1. **带 `[sandbox:` 前缀的拒绝来自 DSH 的策略层**，是你的请求在到达那个对象之前就被判为越界，不是 Windows 的原生报错。这种情况改 `icacls` 一定无效，改多久都没用。
2. **`拒绝访问` / `WinError 5` 来自 Windows 对象层**：要么是 DACL，要么是完整性标签。同一句错误对应两种原因，必须靠「换一个终端再跑一次」的对照把两者分开。
3. **在 DACL 里看到自己的账号有 Modify，不等于沙箱里的进程能写**。Windows 版的 DSH 把子进程放进受限令牌、并降到低完整性级别；一次写要同时满足三个条件：路径在策略允许的范围内、DACL 里有能给受限令牌用的写授权、对象完整性标签不高于进程。三者缺一，症状都是「拒绝」。

## 1. 症状：六种样子，别混在一起修

### S1 报错带 `[sandbox:` 前缀

```
[sandbox: file access denied under workspace-write mode]
```

含义：DSH 在策略层直接拒绝，写请求没有落到那个对象上。拿到这句文本时先查策略（路径、模式、后端），不要先怀疑 ACL。

有一条必须知道：**Windows 下「额外可写根」只对 DSH 的文件工具生效，对 `pwsh` 子进程不生效**。官方文档写明 Windows 进程约束忽略 `additionalWritableRoots`，只有 Harness 自己的文件操作会遵守它们。所以「我明明把目录加进可写白名单了，为什么 `pwsh` 还是写不进」通常就是这一条。

下一步：第 2 步。

### S2 同一个文件，文件工具能写、`pwsh` 里不能写

现象：`write` / `edit` 工具成功写入；`pwsh` 里执行 `Set-Content` 得到 `拒绝访问`。

含义：这是两条执行路径。文件工具走 Harness 自己的文件提供方，不受子进程令牌限制；`pwsh` 走沙箱子进程，受令牌与标签约束。同一个路径两种结果，说明策略层放行了，问题在令牌层。

下一步：第 5 步。

### S3 只有 `拒绝访问` / `Access is denied` / `WinError 5`

含义：进程确实尝试打开了对象，被 Windows 拒绝。这时策略层不是唯一嫌疑，问题在 DACL 或完整性标签。

下一步：第 3、4、5 步。

### S4 DACL 看起来完全正常，仍然失败

现象：`icacls` 里你的账号有 `(M)` 或 `(F)`，继承也开着，普通窗口能写，只有 DSH 里失败。

含义：令牌层。受限令牌的 restricting SID 列表里没有能匹配的写授权，或者目标对象的完整性标签比进程高。这种情况继续调 DACL 是无效劳动。

下一步：第 5 步。

### S5 工作区根能写，里面个别子目录不能写

含义：这些目录的继承被切断，或者它们是从别处复制、解压、由别的工具创建的，没有继承到工作区的写授权与低完整性标签。典型来源：另一个终端里手工创建的目录、从压缩包解出来的目录、从旧位置整目录搬过来的目录。

下一步：第 3、4 步。

### S6 报错其实不是权限问题

- `SANDBOX_UNAVAILABLE` / `SANDBOX_PREPARATION_FAILED`：沙箱后端没有起来（fail-closed），不是权限拒绝。
- read-only 模式下 `pwsh` 进入 ConstrainedLanguage，`[System.IO.File]::WriteAllText` 这类调用报 “Cannot invoke method” 之类的语言模式错误：这是 PowerShell 语言模式限制，不是拒绝。

这两类去改 ACL 都是白费时间。

## 2. 判定：六步，按顺序走

先看一张总图，再逐条执行：

```text
报错文本
├─ 带 [sandbox: 前缀 ──────────────> 策略层：第 2 步（路径、重解析点、模式）
├─ 拒绝访问 / WinError 5
│   ├─ 在 DSH 之外做同一操作也失败 ──> DACL 或所有权：第 3、4 步
│   └─ 只有 DSH 里失败 ─────────────> 令牌或完整性标签：第 5 步
├─ 找不到路径 / 名字不合法 ─────────> 路径问题，不是权限
└─ SANDBOX_UNAVAILABLE 等 ─────────> 沙箱后端没起来，不要动 ACL
```

先约定两件事：

- **诊断命令可以在 DSH 的 `pwsh` 里跑**：只读操作不受沙箱策略限制，但 read-only 模式会把 `pwsh` 切到 ConstrainedLanguage（S6），`[System.IO.File]::WriteAllText`、`[System.IO.DriveInfo]::new` 这类 .NET 静态调用会直接报语言模式错误。所以本节的诊断一律用 cmdlet（`Get-Item`、`Get-ChildItem`、`Get-Acl`、`Get-CimInstance`、`icacls`）；确实只能用 .NET 类型完成的判断，在 read-only 下不可用，需要 workspace-write 模式。先确认当前模式：`$ExecutionContext.SessionState.LanguageMode`。
- **修复命令分两种执行位置**：
  - 改 ACL、改所有权、改完整性标签的（F2、F3、F4、F5 后半段）：在 DSH 之外的普通 PowerShell 窗口里跑。打开方式：在资源管理器里进入目标目录，地址栏输入 `powershell` 回车，窗口的当前目录就是那个目录。沙箱子进程的令牌只被授予写数据，改 DACL 不在它的权限里（附录 A 观察 5 有实测）；就算能改，在沙箱里切断继承也没有回滚手段。
  - 改环境变量的（F5 前半段的 `TEMP`/`TMP`）：在 DSH 的会话里设置才有效，而且要和使用它的命令放在同一次执行里。

### 第 1 步：给报错归类

| 你看到的文本 | 层 | 处理 |
| --- | --- | --- |
| `[sandbox: file access denied under workspace-write mode]` | 策略 | 第 2 步 |
| `拒绝访问` / `Access is denied` / `WinError 5` / `UnauthorizedAccessException` | 对象或标签 | 第 3、4、5 步 |
| `PermissionError: [WinError 5]`（Python） | 对象或标签 | 第 5 步 |
| `The system cannot find the path specified` | 路径 | 不是权限，先修路径 |
| `SANDBOX_UNAVAILABLE` / `SANDBOX_PREPARATION_FAILED` | 后端 | 重装或重启 DSH，不要动 ACL |
| 目录列举结果为空但没有报错 | 对象或标签 | 第 3、5 步 |

归类之后只走一条路，不要同时改三层。

### 第 2 步：这个路径到底在不在工作区里

工作区根不是「你心里想的那个项目目录」，而是会话的 cwd：官方文档写明普通工具调用的 `workspaceRoot` 从调用会话不可变的 cwd 派生。也就是说，**在哪个目录启动 DSH，哪个目录就是工作区根**。

在 DSH 的 `pwsh` 里跑下面这段（`-Path` 传你要检查的路径，`.` 表示当前目录）。如果你之前 `cd` 去过别处，先回到工作区根，或者用 `-Workspace` 明确指定工作区根：

```powershell
function Test-InsideWorkspace {
    param(
        [string]$Path = '.',
        [string]$Workspace = (Get-Location).Path
    )
    $ws = (Resolve-Path -LiteralPath $Workspace).Path.TrimEnd('\')
    $t  = (Resolve-Path -LiteralPath $Path).Path
    [pscustomobject]@{
        Workspace = $ws
        Target    = $t
        Inside    = ($t -ieq $ws) -or $t.StartsWith($ws + '\', [System.StringComparison]::OrdinalIgnoreCase)
    }
}

Test-InsideWorkspace -Path .
```

三条读法：

- `Inside = False`：目标在工作区之外，S1 是预期行为。修法是第 3 节的 F1，不是 ACL。
- `Inside = True` 但报 S1：多半是路径里有重解析点（junction / 符号链接 / 映射盘），策略按解析后的物理路径判定。用下面两条确认：

```powershell
Get-Item -LiteralPath . | Select-Object FullName, LinkType, Target
Get-ChildItem -Force -Attributes ReparsePoint | Select-Object Name, LinkType, Target
```

- `Inside = True` 且报 `拒绝访问`：策略层已放行，进入第 3 步。

### 第 3 步：DACL 里有没有拒你的东西

```powershell
icacls .
```

读法（标志位是英文缩写，不随系统语言变化）：

| 标志 | 含义 |
| --- | --- |
| `(I)` | 这条 ACE 是从父目录继承来的，不是在本对象上设置的 |
| `(OI)` | 对象继承：会往下传给文件 |
| `(CI)` | 容器继承：会往下传给子目录 |
| `(IO)` | 仅继承：只往下传，不作用于本对象 |
| `(DENY)` | 拒绝 ACE。它的优先级高于同一层级的允许 ACE |
| `(F)` `(M)` `(RX)` `(W)` `(D)` | 完全控制 / 修改 / 读执行 / 只写 / 删除 |
| `(DC)` | 删除子项 |
| `Mandatory Label\Low Mandatory Level:(I)(OI)(CI)(NW)` | 完整性标签（不是 DACL 的一部分），见第 5 步 |

两条判定规则：

1. **先看有没有 `(DENY)`**。icacls 保持 ACE 的规范顺序：显式拒绝、显式允许、继承拒绝、继承允许。看到 `(DENY)` 就先处理它，不要在同一对象上叠加 `grant`，否则你只是加了一条永远不生效的允许。
2. **不要数 ACE 条数**。可继承的 ACE 会占两行：一条 `(OI)(CI)` 作用于本对象，一条带 `(IO)` 只往下传；`Get-Acl` 同样给两条，其中一条的权限显示为整数（例如 `268435456`，即 `0x10000000`）。条数没有诊断价值，看 `AccessControlType` 与 `IdentityReference` 才有。

想看结构化视图：

```powershell
(Get-Acl .).Access |
    Select-Object AccessControlType, IsInherited, FileSystemRights, IdentityReference |
    Format-Table -AutoSize
```

`icacls` 的 `/findsid` 可以按 SID 反查：`icacls . /findsid *S-1-1-0 /t /c` 会列出 DACL 里含 Everyone 的对象（继承来的也算）。但继承标志决定它落在哪些对象上：带 `(CI)` 的 ACE 只到目录，文件上查不到是正常的，不代表没有继承拒绝。

### 第 4 步：继承还通着吗

```powershell
(Get-Acl .).AreAccessRulesProtected
```

`True` 表示这个对象的继承已被切断（DACL 处于保护状态），父目录给的 ACE 不会下来。这时你在父目录做的授权对它无效，必须显式恢复继承（F3）或重置（F4）。

同时看一眼父目录：

```powershell
(Get-Acl ..).AreAccessRulesProtected
```

如果父目录也是 `True`，说明切断发生在更高层，逐级向上找。

### 第 5 步：令牌与完整性标签（最容易被跳过的一步）

判定方法只有一个可靠的：**在 DSH 之外做同一件事，再在 DSH 里做一遍**。用同一个账号，两个窗口都不要用「以管理员身份运行」。

```powershell
# 先在普通 PowerShell 窗口里执行这三条，确认能成功
Set-Content -Path .\.probe.txt -Value 'ok'
Get-Content -Path .\.probe.txt
Remove-Item -Path .\.probe.txt
```

```powershell
# 再到 DSH 的 pwsh 里执行同样三条
Set-Content -Path .\.probe.txt -Value 'ok'
Get-Content -Path .\.probe.txt
Remove-Item -Path .\.probe.txt
```

- 普通窗口成功、DSH 里失败 → 差异只能来自令牌（受限 SID 或低完整性），不是 DACL 本身。去做 F5 或 F6，别在这里继续清权限。
- 两边都失败 → 是 DACL 或所有权问题，做 F2、F3、F4。

再用 `icacls .` 看标签行：

- 输出里如果有一行形如 `Mandatory Label\Low Mandatory Level:(I)(OI)(CI)(NW)`，就是这个对象的完整性标签：`NW` 表示低完整性进程不能往上写。工作区树里这一行通常是 Low 且带 `(I)`（继承来的）。
- 如果目标目录及其父目录都没有这一行，它多半还停在 Medium。按微软的定义，**没有完整性标签的对象按 Medium 处理**，而低完整性进程不能写 Medium 对象，哪怕 DACL 明写着允许写。

标签名会随系统语言显示，但格式与 `(NW)`、`(I)`、`(OI)`、`(CI)` 这些标志不变；判断时只认标志。

### 第 6 步：路径与文件系统

```powershell
# 当前目录所在卷的文件系统类型（read-only 下同样可用，不含 .NET 静态调用）
Get-CimInstance -ClassName Win32_LogicalDisk |
    Where-Object { $_.DeviceID -eq ((Get-Location).Drive.Name + ':') } |
    Select-Object DeviceID, FileSystem
```

看 `FileSystem` 一列：

- 不是 `NTFS`（例如 FAT32、exFAT）：这类位置没有可用的 DACL 语义，沙箱要加的授权 ACE 落不下去。不要把它当工作区，换到本地 NTFS 卷。
- 查不到任何行（路径不在盘符上，例如 UNC 共享）：同样不要当工作区。
- 是 `NTFS` 但路径经过 junction、符号链接、映射盘、或位于 UNC 共享：回到第 2 步，用解析后的物理路径重新判断。

## 3. 修复：按层给命令

执行位置见 §2 开头：改 ACL 的命令在 DSH 之外跑，改环境变量的在 DSH 会话里跑。需要管理员权限的步骤会单独标注。

### F1 策略层：把目标放进工作区

```powershell
# 在项目根目录启动 DSH：启动命令时所在的目录就是工作区根
dsh web
```

```powershell
# 已经在会话里时，确认工作区根是哪个目录
(Get-Location).Path
```

要写工作区之外的目录，三条路，按推荐顺序：

1. 把那个目录挪进工作区，让写入发生在工作区内。
2. 重新在正确的目录启动 DSH（换了启动目录就等于换了工作区根，旧会话的 cwd 不会自动跟着变）。
3. 对这一次操作发起升权，批准后该次执行以 `danger-full-access` 运行。这是一次性授权，不要把它设成默认值，也不要用它来绕过日常写入问题。

注意「额外可写根」在 Windows 上只对文件工具生效：文件工具能写、`pwsh` 不能写，正是这个原因。

### F2 只在确认之后，移除某一条特定的拒绝 ACE

先查，不要直接删。下面一条只读：

```powershell
# 只查不改：看当前目录树的 DACL 里有没有 Everyone 的 ACE
icacls . /findsid *S-1-1-0 /t /c
```

命中会打出 `SID Found: <路径>`；一条都没有时输出 `No files with a matching SID was found`。

**如果命中的是 `Everyone:(CI)(DENY)(DC)` 这一行，不要动它。** 这是 DSH 沙箱自己放的删除约束：`(DC)` 是删除子项，`(CI)` 让它跟着工作区根往每个子目录继承。它只拒绝删除、不拒绝写入，所以它不是写不进去的原因——删掉它不会修好任何东西，只会削弱沙箱的删除保护。核对方法：`(Get-Acl .).Access` 里那条 ACE 的 `AccessControlType` 是 `Deny`、`FileSystemRights` 显示 `DeleteSubdirectoriesAndFiles`、身份是 `Everyone`。它不带 `(I)` 就是在工作区根上显式设置的，子目录上带 `(I)` 的是继承下来的那一份；两种都别删。

这和 §4 第 3 条不矛盾：那条反对的是**自己动手**给 Everyone 加拒绝——尤其是 `(W)`/`(F)` 这类宽权限再带 `(OI)(CI)` 的写法，它会盖住继承来的允许，之后在哪一层补授权都无效；DSH 自己放的这条只收窄删除，是产品的一部分，不要用 `/remove:d` 把它当残留清掉。

只有在你已经确认「这条显式拒绝属于某个特定 SID、与 DSH 无关、而且确实挡住了你要做的操作」时才移除，并且只针对那一个 SID：

```powershell
# 先备份；$sid 换成你在 icacls . 里确认过的那一个账号名或 SID
icacls . /save acl-before-remove.txt /t /c
$sid = "$env:USERNAME"
icacls . /remove:d "$sid"
icacls .    # 复核：目标 ACE 消失，Everyone:(CI)(DENY)(DC) 与 S-1-4-* 那行仍在
```

风险：`/remove:d` 会删掉该对象上所有匹配的显式拒绝 ACE，等于放宽权限，而且没有撤销键，只能靠备份回滚（同一目录、同一份备份文件：`icacls . /restore acl-before-remove.txt /c`）。所以先 `/findsid` 再动手，先不加 `/t` 只试一个对象，确认无误再扩大范围。**不要用 `*S-1-1-0` 做 `/remove:d` 的参数**——那正是把 DSH 的删除约束一起清掉的写法。

说明：

- `*S-1-1-0` 是 Everyone 的 SID。用 SID 而不是名称，可以避开系统语言与内置组本地化的问题；icacls 接受 `*` 前缀的数字 SID。
- 继承来的拒绝 ACE 属于父目录，在子对象上删不掉；要回到提供它的父目录去处理。
- `/remove:d` 只删拒绝 ACE；要连允许一起删是 `/remove:g`，通常不需要。

### F3 恢复继承

```powershell
# 只对当前目录：重新打开继承，父目录的 ACE 立刻生效
icacls . /inheritance:e
```

```powershell
# 整个子树：会遍历子目录与文件，遇到错误继续
icacls . /inheritance:e /t /c /q
```

`/inheritance:e` 打开继承；`/inheritance:r` 是相反方向（关掉继承并删掉现有的继承 ACE），除非你明确要隔离一个目录，不要用 `r`。

### F4 重置为继承来的默认 ACL（先备份）

```powershell
# 备份当前 ACL，出问题时可以还原
icacls . /save acl-backup.txt /t /c
```

```powershell
# 以管理员身份运行：把所有权收回来
takeown /f "$PWD" /r /d y
```

```powershell
# 以管理员身份运行：把 ACL 重置为从父目录继承的默认值
icacls . /reset /t /c /q
```

```powershell
# 需要回滚时（在同一目录、同一份备份文件上执行）
icacls . /restore acl-backup.txt /c
```

`/reset` 会丢掉这个目录树上所有手工加的显式 ACE，包括其他工具需要的。所以先 `/save`，别跳过备份。

### F5 令牌与标签：私有 DACL、临时目录

最常见的现场：Python 与 pytest。

```text
PermissionError: [WinError 5] Access is denied
```

原因有两条叠加：

- Python 的 `tempfile.mkdtemp()` / `TemporaryDirectory()` 创建的目录「只有创建者能读、能写、能搜索」（官方文档原文），在 Windows 上表现为一条只含创建者本人的 DACL。这样的 DACL 没有给受限令牌的 restricting SID 留下任何写授权。
- 如果这个临时目录还落在工作区之外（例如用户级临时目录），它是 Medium 完整性，低完整性的沙箱子进程连标签层都过不去。

最省事的修法：把临时目录指到工作区内，让它同时继承工作区的写授权和低完整性标签。注意 DSH 的 `pwsh` 每次调用都是新进程，环境变量不会跨调用保留，所以「设置」和「使用」要放在同一段命令里；或者把 `TEMP`/`TMP` 设在启动 DSH 的那个环境里，让所有会话继承。

```powershell
$tmp = Join-Path (Get-Location) '.dsh-tmp'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$env:TEMP = $tmp
$env:TMP  = $tmp
"TEMP=$env:TEMP"
```

pytest 用同一套设置，并显式指定 basetemp，避免它自己去挑目录：

```powershell
$tmp = Join-Path (Get-Location) '.dsh-tmp'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$env:TEMP = $tmp
$env:TMP  = $tmp
python -m pytest --basetemp .\.pytest-tmp
```

不能搬走时的兜底（只对临时目录用，别用在项目目录上）：

```powershell
# 给该目录树补一条 Everyone 的修改权限；作用域仅此目录，属于权限放宽，自行权衡
icacls . /grant *S-1-1-0:(OI)(CI)(M)
```

但注意：**这条只在标签层已经放行时才有效**。如果 `icacls .` 显示该目录没有 Low 标签（它还是 Medium），补 DACL 也不会成功，必须先把标签降下来：

```powershell
# 以管理员身份运行：把该目录树的完整性标签设为 Low，让低完整性的子进程可以写
icacls . /setintegritylevel (CI)(OI)Low
```

降标签等于降低这棵树的保护级别（低完整性进程可以修改它），只在确实无法搬进工作区的临时/缓存目录上做。

### F6 路径别名与非 NTFS

```powershell
# 看当前目录本身是不是重解析点、指向哪里
Get-Item . | Select-Object FullName, LinkType, Target
```

```powershell
# 列出目录里所有重解析点项（junction、符号链接、挂载点）
Get-ChildItem -Force -Attributes ReparsePoint | Select-Object Name, LinkType, Target
```

处理原则：把工作区放在本地 NTFS 的真实目录上，不用 junction 或映射盘把它接到别处；不要把网络共享当工作区；需要共享代码时，用复制而不是链接。

## 4. 预防：让下一次不用排查

1. **工作区就是启动目录**。在项目根启动 DSH；不要在一个无关目录启动之后再「指过去」，那只会得到 S1。
2. **目录让 DSH 建**。需要新目录时用文件工具或沙箱内的命令创建，让写授权与低完整性标签跟着继承下来；从压缩包、别的机器、旧位置搬来的目录，先按第 3、5 步验一遍再往里写。
3. **不要手工「清权限」**。对目录做「删除所有权限」「仅自己可访问」「给 Everyone 加拒绝」是最常见的自伤操作：继承拒绝一旦写在工作区根上，会跟着整棵子树走，之后在哪一层补的授权都会被它盖住。要重置就用 `/reset`，并且先 `/save` 备份。
4. **不要在 DSH 运行中重命名或移动工作区根**。会话记的是启动时的绝对路径，路径一旦变了，后续写入全部落在策略层。
5. **脚本里做写前探测**。写之前先试建一个探针文件，把 `WinError 5` 翻译成「目录不可写（权限或沙箱）」，而不是让流程跑到一半炸掉：

```powershell
function Test-Writable {
    param([string]$Path = '.')
    $probe = Join-Path $Path ('.dsh-write-probe-' + [guid]::NewGuid().ToString('N'))
    try {
        Set-Content -LiteralPath $probe -Value 'probe' -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
        'WRITABLE'
    } catch {
        'DENIED: ' + $_.Exception.Message
    }
}

Test-Writable -Path .
```

6. **临时目录固定在工作区内**。在同一次执行里设好 `TEMP` 与 `TMP` 再启动进程（F5），给 pytest 显式 `--basetemp`。这样 Python 建出来的「仅创建者」目录也长在工作区里，能继承到写授权与低完整性标签，问题在第 1 步就不会出现。
7. **出问题先存证据**。修复前把当前状态存一份，回头能对比，也能拿去问人：

```powershell
icacls . > acl-snapshot.txt
(Get-Acl .).Access | Format-List * >> acl-snapshot.txt
Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID, FileSystem >> acl-snapshot.txt
```

## 附录 A：这套判定是怎么验出来的

下面是写这份备忘时实际跑过的观察。环境是一台中文界面的 Windows 11（内部版本 26100），命令都在 DSH 的沙箱 `pwsh` 里执行；观察 5 里有一次被拒绝的 ACL 变更尝试，前后 DACL 逐字一致，没有留下改动。

**观察 1：工作区的写授权不是你的账号，而是一条 `S-1-4-*` 的能力 SID ACE。**

`icacls` 在工作区根上显示：`Administrators`、`SYSTEM`、`Authenticated Users`、`Users` 之外，还有一行身份显示为原始 SID（形如 `S-1-4-*`）、权限为 `(W,D,DC)` 的 ACE。它不是任何人类账号，而是沙箱侧的能力 SID。这解释了为什么「我的账号有 Modify」不能推出「沙箱能写」：限制在于令牌的 restricting SID 列表，和你的授权是两回事。

这条 ACE 的来源要用 `/findsid` 与 `Get-Acl` 对照判断，不能一律称为「继承」：带 `(I)`（`Get-Acl` 里 `IsInherited` 为 `True`）才是从父对象继承来的，不带 `(I)` 就是在该对象上显式设置的。逐层对照时会看到两者并存——工作区根上这一行常常不带 `(I)`，由 DSH 文件工具新建的文件上才显示成 `S-1-4-*:(I)(W,D,DC)`。所以只看「有没有这条 ACE」不足以下结论，要连 `(I)` 一起看。由 DSH 文件工具新建的文件会自动带上同样的 ACE —— 这正是「让 DSH 自己建文件」能避开这类故障的原因。

**观察 2：完整性标签在 `icacls` 里有，在 `Get-Acl` 里没有。**

同一目录的 `icacls` 输出有一行 `Mandatory Label\Low Mandatory Level:(I)(OI)(CI)(NW)`；而 `(Get-Acl .).Access` 只返回 DACL 里的允许/拒绝 ACE，看不到这一行。所以「用 Get-Acl 看一切正常」是一个不完整的结论：标签在 SACL 里，不在 DACL 里。新建的文件上是 `Mandatory Label\Low Mandatory Level:(I)(NW)`，同样是继承来的。

**观察 3：`/findsid` 反查时，`(CI)` 只命中目录。**

`icacls . /findsid *S-1-1-0 /t /c` 在一个工作区子树上执行：处理 35 个对象，命中 10 个，命中的全是目录；同一批目录里的文件单独查则返回 `No files with a matching SID was found`。这不是 `/findsid` 漏查继承 ACE（继承 ACE 就在子对象的 DACL 里，能被找到），而是那条 Everyone 拒绝带 `(CI)`（容器继承），本来就不会落到文件上。只查文件会得到「没有拒绝」的错误结论。

**观察 4：`icacls` 多出来的那一行是标签，不是 ACE。**

同一个目录：`icacls` 打出 10 条 ACE 加 1 行 `Mandatory Label\Low Mandatory Level:(I)(OI)(CI)(NW)`；`(Get-Acl .).Access` 也是 10 条。两边 ACE 条数一致。另外 `Get-Acl` 会把带继承标志的那条 ACE 的权限显示成整数（例如 `268435456`，即 `0x10000000`），对应 `icacls` 里的 `(IO)(F)` 那一行。

**观察 5：在沙箱里能读 DACL，不能改 DACL，而且失败是干净的。**

对一个刚由 DSH 文件工具写出的工作区文件（示例里记为 `demo.txt`）执行拒绝变更：

```powershell
icacls .\demo.txt /deny *S-1-5-32-580:(R)
```

结果：stderr 一行 `.\demo.txt: Access is denied.`，退出码 5，统计行是 `Successfully processed 0 files; Failed processing 1 files`。紧接着用 `icacls .\demo.txt` 读出来的 DACL 与执行前逐字一致——失败的变更没有留下半成品。对同一个文件执行 `/remove:d` 同样被拒。那次尝试想加的是一条指向「不在任何令牌里」的 SID 的拒绝 ACE，所以即使加成功也不会影响任何账号。

对照：同一时刻，`icacls .\demo.txt`（读 ACL）、`Get-Content`（读内容）、`Get-Acl` 全部成功。

结论：沙箱子进程的令牌只被授予写数据，没有 WRITE_DAC。所以 ACL 修复必须在 DSH 之外的窗口做；反过来也有一条判定规则——**在沙箱里改 ACL 时看到 `Access is denied`，说明你正处在令牌层，不是命令写错了**。

## 附录 B：来源

- DSH 官方子系统文档《进程沙箱》：模式定义、`workspaceRoot` 由会话 cwd 派生、Windows 进程约束忽略额外可写根、`SANDBOX_UNAVAILABLE` 等 fail-closed 错误。https://deepseek-harness.github.io/deepseek-harness/reference/subsystems/sandbox.md
- DSH 官方实现说明《Windows sandbox rung: raw ACL restricted tokens》：Windows 后端使用 WRITE_RESTRICTED 受限令牌、restricting SID 携带工作区能力与私有临时目录能力、令牌降为低完整性。https://github.com/deepseek-ai/deepseek-harness/blob/HEAD/.agents/notes/implemented/feature/2026-08-08-windows-acl-restricted-token-sandbox.md
- Microsoft Learn《icacls》：`/deny`、`/remove:d`、`/inheritance:e|d|r`、`/reset`、`/save`、`/restore`、`/setintegritylevel`、`/findsid` 的语义，以及「数字 SID 需加 `*` 前缀」和 ACE 规范顺序。https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
- Microsoft Learn《Order of ACEs in a DACL》：显式拒绝先于显式允许、继承 ACE 排在显式 ACE 之后。https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl
- Microsoft Learn《Mandatory Integrity Control》：低完整性主体不能写中等完整性对象，即使 DACL 允许；没有完整性标签的对象按中等处理。https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
- Microsoft Learn《takeown》：`/r`、`/d y` 的用法。https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown
- Python 文档《tempfile》：`mkdtemp()` / `TemporaryDirectory()` 创建的目录「只有创建者可读、可写、可搜索」。https://docs.python.org/3/library/tempfile.html
- 第三方插件文档（旁证）：Windows 上确实会看到 `[sandbox: file access denied under workspace-write mode]` 这条文本。https://dshbase.com/zh/plugins/dsh-bash-win/

## 快速诊断（脚本）

仓库内附只读诊断脚本 `diagnose-dsh-acl.ps1`：给它一个路径，它输出三行结论，不写文件、不改 ACL、不联网，兼容 PowerShell 5.1 与 7。

```powershell
pwsh -NoProfile -File .\diagnose-dsh-acl.ps1 -Path .
```

输出字段：

- `VERDICT=`：`策略` / `DACL` / `继承` / `路径` / `正常` / `未知`
- `EVIDENCE=`：一句话证据（含关键 ACE 片段或属性值）
- `NEXT=`：一句话下一步

注意：工作区根上 `Everyone:(CI)(DENY)(DC)` 是 DSH 沙箱自带的防删除保护，脚本会判 `策略` 并明确提示**不要移除**。
