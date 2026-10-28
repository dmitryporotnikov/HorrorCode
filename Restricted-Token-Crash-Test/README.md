# Restricted-token Windows crash test

Keep both EXEs together. Run from PowerShell:

```powershell
.\wer-restricted-launcher.exe
```

For Untrusted instead of Low integrity:

```powershell
.\wer-restricted-launcher.exe -integrity untrusted
```

No installer, Go runtime, Visual C++ redistributable, AppContainer profile, or
administrator rights are required to run the Windows x64 binaries. Both pre-built EXEs are
signed with the same self-signed test certificate as the original application.
The certificate is included for inspection and is not automatically trusted.

## Launcher

The normal-user Go launcher:

- Creates a restricted primary token using `CreateRestrictedToken` and
  `DISABLE_MAX_PRIVILEGE` (Windows retains `SeChangeNotifyPrivilege`).
- Makes the current user and Administrators SIDs deny-only. An Administrators SID
  absent from a standard account's token stays absent.
- Adds Everyone (`S-1-1-0`), Users (`S-1-5-32-545`), and RESTRICTED (`S-1-5-12`)
  as restricting SIDs. Windows performs a second access check against this list;
  the entries are alternatives, not three independent checks.
- Sets `TokenIntegrityLevel` to Low by default, or Untrusted when requested.
- Uses `CreateProcessAsUserW` with `CREATE_SUSPENDED`, no inherited handles,
  and `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` containing
  `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON`.
- Assigns the child to a job with all eight classic UI restrictions (`0xFF`):
  handles, read/write clipboard, system/display settings, global atoms, desktop,
  and exit Windows. The job also has active-process limit 1 and kill-on-close.
- Verifies the child's actual restricted token, deny-only SIDs, integrity,
  restricting SIDs, enabled privileges, win32k mitigation and job membership
  before resuming it. Failure stops the child; restrictions are not weakened.

To give the child read/execute access to its own image, the launcher stages a
copy in a temporary folder and grants Everyone read/execute on only that folder
and EXE. The original files' permissions are unchanged. On normal completion,
the temporary directory is removed; forced termination can leave temporary files.

Go disables WER in its own process error mode. The launcher clears only
`SEM_NOGPFAULTERRORBOX` around process creation so the native child does not
inherit WER suppression, then restores the launcher's original mode.

No alternate desktop is created. Win32k lockdown and the job's UI restrictions
are used here. This is a test of the requested Windows primitives; it does not
implement Firefox/Chromium's complete sandbox, broker, or network policy.

## Native child

The child is C rather than Go to avoid Go's runtime exception handlers and WER
settings. Its custom entry point calls `Sleep(5000)`, then raises a noncontinuable
`0xC0000005` exception using `RaiseException`. It installs no exception handler or
crash reporter and never calls `SetErrorMode`, `SetUnhandledExceptionFilter`, or
`MiniDumpWriteDump`. There is no C runtime. Its only DLL import is kernel32, with
`Sleep`, `RaiseException`, and unreachable fallback `ExitProcess`.

The child uses the Windows subsystem to avoid console initialization, but has no
GUI or user32/gdi32 imports. The first console-subsystem build failed during
initialization with `0xC0000142`; the console-free build passed with the same
token, job and mitigation restrictions.

## Results on this machine

Both Low and Untrusted tests passed from a non-elevated user process:

- The suspended child's token and win32k checks passed.
- The child exited with `0xC0000005`.
- The host Application log recorded event 1000 (Application Error) and event
  1001 (Windows Error Reporting, APPCRASH).
- WER archived a crash report. Windows crash handling extended total child
  process lifetime to approximately 7.7 seconds; the exception is raised after
  five seconds of the child's entry point running.

Look in Event Viewer > Windows Logs > Application for `wer-native-crasher.exe`.
The faulting module can be KERNELBASE.dll because this test uses `RaiseException`.
WER/AeDebug behavior still depends on the destination computer's policy and
debugger configuration.

## Build from source

The `source` folder contains the Go launcher, Go module, native C child, and
native build script. From `source`, with Go available:

```powershell
go build -trimpath -o ..\wer-restricted-launcher.exe ./cmd/restricted
```

From an x64 Native Tools Command Prompt for Visual Studio, run:

```cmd
source\restricted\build-native.cmd
```

Copy the resulting `source\restricted\wer-native-crasher.exe` beside the launcher.
Rebuilt files are unsigned; the supplied binaries carry the test signatures.

References:

- https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
- https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
- https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
