[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-ScriptAst([string]$Path) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) {
        throw "PowerShell parser rejected $Path`: $($parseErrors -join '; ')"
    }
    return $ast
}

function Assert-NoVariable([Management.Automation.Language.Ast]$Ast, [string]$Name) {
    $uses = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.VariableExpressionAst] -and
            $node.VariablePath.UserPath -ieq $Name
    }, $true))
    if ($uses.Count -ne 0) {
        throw "Script must not use the automatic PowerShell variable `$$Name."
    }
}

function Assert-NoInstanceAclApi([Management.Automation.Language.Ast]$Ast) {
    $calls = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
            $node.Member.Value -in @('GetAccessControl', 'SetAccessControl')
    }, $true))
    if ($calls.Count -ne 0) {
        throw 'Windows ACL compatibility requires Get-Acl/Set-Acl, not instance ACL methods.'
    }
}

function Assert-CommandPresent(
    [Management.Automation.Language.Ast]$Ast,
    [string]$Name) {
    $commands = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ieq $Name
    }, $true))
    if ($commands.Count -eq 0) {
        throw "Expected compatibility command $Name was not found."
    }
}

$membershipPath = Join-Path $PSScriptRoot 'survival-dev-membership-fixture-repeat.ps1'
$privateSecretsPath = Join-Path $PSScriptRoot 'survival-dev-private-secrets.ps1'
$mailboxInputsPath = Join-Path $PSScriptRoot 'survival-dev-mailbox-build-inputs.ps1'

$membershipAst = Get-ScriptAst $membershipPath
Assert-NoVariable $membershipAst 'Matches'

foreach ($path in @($privateSecretsPath, $mailboxInputsPath)) {
    $ast = Get-ScriptAst $path
    Assert-NoInstanceAclApi $ast
    Assert-CommandPresent $ast 'Get-Acl'
    Assert-CommandPresent $ast 'Set-Acl'
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Output 'survival-dev PowerShell compatibility contracts: PASS (Windows ACL runtime skipped)'
    exit 0
}

. $privateSecretsPath
. $mailboxInputsPath

$work = Join-Path ([IO.Path]::GetTempPath()) (
    'deep-powershell-acl-compat-' + [Guid]::NewGuid().ToString('N'))
try {
    [void][IO.Directory]::CreateDirectory($work)
    Set-MailboxDirectoryExclusiveWritable $work

    $privateFile = Join-Path $work 'private.txt'
    [IO.File]::WriteAllText($privateFile, ('a' * 64) + "`n")
    Protect-SurvivalDevPrivateFile $privateFile
    Assert-SurvivalDevPrivateFile $privateFile

    $mailboxFile = Join-Path $work 'mailbox-state.json'
    [IO.File]::WriteAllText($mailboxFile, '{}')
    Set-MailboxFileExclusiveWritable $mailboxFile

    $workAcl = Get-Acl -LiteralPath $work
    $fileAcl = Get-Acl -LiteralPath $mailboxFile
    if (-not $workAcl.AreAccessRulesProtected -or
        -not $fileAcl.AreAccessRulesProtected) {
        throw 'Mailbox ACL helpers did not leave protected Windows DACLs.'
    }
} finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}

Write-Output "survival-dev PowerShell compatibility contracts: PASS ($($PSVersionTable.PSVersion))"
