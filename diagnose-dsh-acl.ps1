<#
.SYNOPSIS
  只读诊断一个目录的 ACL 类别：DSH 沙箱保护 / 具体主体 DACL / 继承阻断 / 正常。
.DESCRIPTION
  纯只读：不写文件、不 Set-Acl、不给 icacls 任何写参数、不联网；5.1/7 通用，退出码恒为 0。
  工作区根的 Everyone:(DENY)(DC) 是 DSH 沙箱 ambient-delete 保护，不能建议移除；只有主体为具体用户/组的 DENY 才判 DACL。
.PARAMETER Path
  要诊断的目录路径，缺省为当前目录。
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path = '.'
)

$ErrorActionPreference = 'Stop'

function Out-Result {
    param([string]$Verdict, [string]$Evidence, [string]$Next)
    Write-Output ('VERDICT=' + $Verdict)
    Write-Output ('EVIDENCE=' + $Evidence)
    Write-Output ('NEXT=' + $Next)
}

function ConvertTo-OneLine {
    param([string]$Text, [int]$MaxLength = 300)
    if ($null -eq $Text) { return '' }
    $one = ($Text -replace '\s+', ' ').Trim()
    if ($one.Length -gt $MaxLength) { $one = $one.Substring(0, $MaxLength) + '...' }
    return $one
}

$target = $Path
if ([string]::IsNullOrWhiteSpace($target)) { $target = '.' }

# ---------- 判定 1：路径不存在 / 不是目录 ----------
try {
    $exists = Test-Path -LiteralPath $target
} catch {
    Out-Result '未知' ('路径检测失败：' + (ConvertTo-OneLine $_.Exception.Message)) '换一个可访问的本地绝对路径重试'
    exit 0
}
if (-not $exists) {
    Out-Result '路径' ('路径不存在：' + $target) '确认路径拼写，或先创建该目录'
    exit 0
}
try {
    $isDir = Test-Path -LiteralPath $target -PathType Container
} catch {
    Out-Result '未知' ('类型检测失败：' + (ConvertTo-OneLine $_.Exception.Message)) '用 -Path 指定一个已存在的目录'
    exit 0
}
if (-not $isDir) {
    Out-Result '路径' ('不是目录：' + $target) '本脚本只诊断目录，请改传目录路径'
    exit 0
}
try { $resolved = (Resolve-Path -LiteralPath $target).ProviderPath } catch { $resolved = $target }

# ---------- 判定 3：icacls 只读输出里的 DENY ACE，先按主体分流 ----------
try {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # 5.1：防止原生命令 stderr 升级为终止错误
    try {
        $raw = & icacls.exe $resolved 2>&1
        $icaclsExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $icaclsText = (($raw | ForEach-Object { [string]$_ }) -join "`n")
} catch {
    Out-Result '未知' ('icacls 读取失败：' + (ConvertTo-OneLine $_.Exception.Message)) '在当前用户上下文下用 icacls <路径> 手工确认'
    exit 0
}
if ($icaclsExit -ne 0) {
    Out-Result '未知' ('icacls 退出码 ' + $icaclsExit + '：' + (ConvertTo-OneLine $icaclsText)) '确认路径可访问后用 icacls <路径> 手工确认'
    exit 0
}

$denyPolicy = ''
$denySpecific = ''
foreach ($line in ($icaclsText -split "`r?`n")) {
    if ($line -notmatch '\(DENY\)') { continue }
    $m = [regex]::Match($line, '(?<subject>.*):(?<perms>(?:\([^()]*\))+)\s*$')
    if (-not $m.Success) { continue }
    $subject = $m.Groups['subject'].Value.Trim()
    if ($subject.StartsWith($resolved, [StringComparison]::OrdinalIgnoreCase)) {
        $subject = $subject.Substring($resolved.Length).Trim()
    } elseif ($subject -match '^[A-Za-z]:\\\S*\s+(.+)$') {
        $subject = $Matches[1].Trim()   # 去掉 icacls 回显的路径（含代码页导致的乱码前缀）
    }
    $perms = $m.Groups['perms'].Value
    $leaf = @($subject -split '\s+')[-1]
    $leaf = ($leaf -replace '^\*', '')      # icacls 名称无法解析时写作 *S-1-1-0
    $ace = $subject + ':' + $perms
    $isEveryone = ($leaf -eq 'Everyone') -or ($leaf -eq 'S-1-1-0')
    $hasDC = $perms -match '(?<![A-Za-z])DC(?![A-Za-z])'
    if ($isEveryone -and $hasDC) {
        if ($denyPolicy -eq '') { $denyPolicy = $ace }
    } elseif (-not $isEveryone -and $denySpecific -eq '') {
        $denySpecific = $ace
    }
}
if ($denyPolicy -ne '') {
    Out-Result '策略' ('Everyone 的 (DENY)(DC) 属 DSH 沙箱 ambient-delete 保护，不是 DACL 故障：' + (ConvertTo-OneLine $denyPolicy 200)) '这是 DSH 沙箱的保护，不要移除；工作区访问异常请转查主体成员资格与父目录继承'
    exit 0
}
if ($denySpecific -ne '') {
    Out-Result 'DACL' ('存在具体主体的显式拒绝 ACE：' + (ConvertTo-OneLine $denySpecific 200)) '按主体定向处理，先备份 ACL（icacls /save），再改或删这条 DENY；Everyone 的沙箱保护保持不动'
    exit 0
}

# ---------- 判定 4：继承是否被阻断 ----------
try {
    $acl = Get-Acl -LiteralPath $resolved
    $isProtected = $acl.AreAccessRulesProtected
    $owner = [string]$acl.Owner
} catch {
    Out-Result '未知' ('Get-Acl 读取失败：' + (ConvertTo-OneLine $_.Exception.Message)) '以能读取安全描述符的身份重跑，或手工核对“安全”选项卡'
    exit 0
}
$aceCount = -1
try { $aceCount = $acl.Access.Count } catch { $aceCount = -1 }

if ($isProtected -eq $True) {
    Out-Result '继承' ('AreAccessRulesProtected=True；ACE 数=' + $aceCount + '；Owner=' + $owner) '先确认父目录应下发的权限，再决定是否恢复继承（默认不改）'
    exit 0
}
Out-Result '正常' ('AreAccessRulesProtected=False；未见 Everyone 的 (DENY)(DC)，也未见具体主体的 DENY；ACE 数=' + $aceCount + '；Owner=' + $owner) '只读判据未发现问题；若仍被拒绝，查主体成员资格与父目录'
exit 0