// restricted is a portable restricted-token/job/win32k crash-test launcher.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	k32 = syscall.NewLazyDLL("kernel32.dll")
	a32 = syscall.NewLazyDLL("advapi32.dll")
)

type sidAttributes struct {
	SID        *syscall.SID
	Attributes uint32
}
type startupInfoEx struct {
	Info       syscall.StartupInfo
	Attributes *uintptr
}
type basicLimits struct {
	ProcessTime, JobTime                 int64
	Flags                                uint32
	MinimumWorkingSet, MaximumWorkingSet uintptr
	ActiveProcesses                      uint32
	Affinity                             uintptr
	Priority, Scheduling                 uint32
}
type extendedLimits struct {
	Basic                                                      basicLimits
	IO                                                         [6]uint64
	ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
}

func wide(s string) *uint16 { return syscall.StringToUTF16Ptr(s) }

//go:uintptrescapes
func call(proc *syscall.LazyProc, args ...uintptr) error {
	r, _, err := proc.Call(args...)
	if r == 0 {
		return fmt.Errorf("%s: %w", proc.Name, err)
	}
	return nil
}
func tokenInfo(t syscall.Token, class uint32) ([]byte, error) {
	var size uint32
	a32.NewProc("GetTokenInformation").Call(uintptr(t), uintptr(class), 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil, fmt.Errorf("empty token info class %d", class)
	}
	b := make([]byte, size)
	err := call(a32.NewProc("GetTokenInformation"), uintptr(t), uintptr(class), uintptr(unsafe.Pointer(&b[0])), uintptr(size), uintptr(unsafe.Pointer(&size)))
	return b, err
}
func checkSID(t syscall.Token, class uint32, expected *syscall.SID, deny bool) error {
	b, err := tokenInfo(t, class)
	if err != nil {
		return err
	}
	count := *(*uint32)(unsafe.Pointer(&b[0]))
	offset := unsafe.Offsetof(struct {
		Count uint32
		First sidAttributes
	}{}.First)
	for i := uint32(0); i < count; i++ {
		sa := (*sidAttributes)(unsafe.Pointer(&b[int(offset)+int(i)*int(unsafe.Sizeof(sidAttributes{}))]))
		equal, _, _ := a32.NewProc("EqualSid").Call(uintptr(unsafe.Pointer(sa.SID)), uintptr(unsafe.Pointer(expected)))
		if equal != 0 && (!deny || (sa.Attributes&0x10 != 0 && sa.Attributes&4 == 0)) {
			return nil
		}
	}
	return fmt.Errorf("expected SID missing or wrong attributes in token class %d", class)
}

func run(integrity string) error {
	rid := uint32(0x1000)
	if integrity == "untrusted" {
		rid = 0
	} else if integrity != "low" {
		return fmt.Errorf("integrity must be low or untrusted")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	source := filepath.Join(filepath.Dir(self), "wer-native-crasher.exe")
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("keep wer-native-crasher.exe beside this launcher: %w", err)
	}
	defer in.Close()
	tempRoot := filepath.Clean(os.TempDir())
	dir, err := os.MkdirTemp(tempRoot, "wer-restricted-")
	if err != nil {
		return err
	}
	if filepath.Dir(dir) != tempRoot {
		return fmt.Errorf("unexpected temporary path %s", dir)
	}
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "wer-native-crasher.exe")
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	// The normal and restricting SID checks must both allow the image to load.
	// Grant only read/execute, and only on this temporary directory and EXE.
	for _, path := range []string{dir, target} {
		output, err := exec.Command("icacls.exe", path, "/grant", "*S-1-1-0:(RX)").CombinedOutput()
		if err != nil {
			return fmt.Errorf("temporary image ACL: %w: %s", err, output)
		}
	}

	var original syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE|syscall.TOKEN_ASSIGN_PRIMARY|syscall.TOKEN_ADJUST_DEFAULT, &original); err != nil {
		return err
	}
	defer original.Close()
	user, err := original.GetTokenUser()
	if err != nil {
		return err
	}
	adminSID, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	everyoneSID, err := syscall.StringToSid("S-1-1-0")
	if err != nil {
		return err
	}
	usersSID, err := syscall.StringToSid("S-1-5-32-545")
	if err != nil {
		return err
	}
	restrictedSID, err := syscall.StringToSid("S-1-5-12")
	if err != nil {
		return err
	}
	disabled := []sidAttributes{{SID: user.User.Sid}, {SID: adminSID}}
	restricting := []sidAttributes{{SID: everyoneSID}, {SID: usersSID}, {SID: restrictedSID}}
	var token syscall.Token
	if err := call(a32.NewProc("CreateRestrictedToken"), uintptr(original), 1, uintptr(len(disabled)), uintptr(unsafe.Pointer(&disabled[0])), 0, 0, uintptr(len(restricting)), uintptr(unsafe.Pointer(&restricting[0])), uintptr(unsafe.Pointer(&token))); err != nil {
		return err
	}
	defer token.Close()
	ilSID, err := syscall.StringToSid(fmt.Sprintf("S-1-16-%d", rid))
	if err != nil {
		return err
	}
	label := sidAttributes{SID: ilSID, Attributes: 0x20} // SE_GROUP_INTEGRITY
	sidLen, _, _ := a32.NewProc("GetLengthSid").Call(uintptr(unsafe.Pointer(ilSID)))
	if err := call(a32.NewProc("SetTokenInformation"), uintptr(token), 25, uintptr(unsafe.Pointer(&label)), unsafe.Sizeof(label)+sidLen); err != nil {
		return err
	}

	job, _, lastErr := k32.NewProc("CreateJobObjectW").Call(0, 0)
	if job == 0 {
		return fmt.Errorf("CreateJobObjectW: %w", lastErr)
	}
	defer syscall.CloseHandle(syscall.Handle(job))
	limits := extendedLimits{Basic: basicLimits{Flags: 0x2000 | 8, ActiveProcesses: 1}} // kill on close, process limit
	if err := call(k32.NewProc("SetInformationJobObject"), job, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); err != nil {
		return err
	}
	ui := uint32(0xFF) // HANDLES, clipboard, system/display settings, atoms, desktop, exit windows
	if err := call(k32.NewProc("SetInformationJobObject"), job, 4, uintptr(unsafe.Pointer(&ui)), 4); err != nil {
		return err
	}

	var attrSize uintptr
	initAttrs := k32.NewProc("InitializeProcThreadAttributeList")
	initAttrs.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrSize)))
	if attrSize == 0 {
		return fmt.Errorf("cannot size process attributes")
	}
	attrs := make([]uintptr, (attrSize+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	if err := call(initAttrs, uintptr(unsafe.Pointer(&attrs[0])), 1, 0, uintptr(unsafe.Pointer(&attrSize))); err != nil {
		return err
	}
	defer func() {
		k32.NewProc("DeleteProcThreadAttributeList").Call(uintptr(unsafe.Pointer(&attrs[0])))
		runtime.KeepAlive(attrs)
	}()
	mitigation := uint64(1) << 28 // WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
	if err := call(k32.NewProc("UpdateProcThreadAttribute"), uintptr(unsafe.Pointer(&attrs[0])), 0, 0x20007, uintptr(unsafe.Pointer(&mitigation)), 8, 0, 0); err != nil {
		return err
	}
	si := startupInfoEx{Attributes: &attrs[0]}
	si.Info.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	// Go suppresses WER in its process error mode. Children inherit that mode.
	// Clear only this flag while creating the native child; the child sets no handlers.
	runtime.LockOSThread()
	errorMode, _, _ := k32.NewProc("GetErrorMode").Call()
	k32.NewProc("SetErrorMode").Call(errorMode &^ 2)
	err = call(a32.NewProc("CreateProcessAsUserW"), uintptr(token), uintptr(unsafe.Pointer(wide(target))), uintptr(unsafe.Pointer(wide(syscall.EscapeArg(target)))), 0, 0, 0,
		0x80000|4|0x08000000, 0, uintptr(unsafe.Pointer(wide(dir))), uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	k32.NewProc("SetErrorMode").Call(errorMode)
	runtime.UnlockOSThread()
	runtime.KeepAlive(mitigation)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)
	finished := false
	defer func() {
		if !finished {
			syscall.TerminateProcess(pi.Process, 1)
		}
	}()
	if err := call(k32.NewProc("AssignProcessToJobObject"), job, uintptr(pi.Process)); err != nil {
		return err
	}

	// Check the child itself while suspended; do not silently weaken restrictions.
	var actual syscall.Token
	if err := syscall.OpenProcessToken(pi.Process, syscall.TOKEN_QUERY, &actual); err != nil {
		return err
	}
	defer actual.Close()
	if err := call(a32.NewProc("IsTokenRestricted"), uintptr(actual)); err != nil {
		return err
	}
	il, err := tokenInfo(actual, 25)
	if err != nil {
		return err
	}
	actualIL := (*sidAttributes)(unsafe.Pointer(&il[0]))
	equal, _, _ := a32.NewProc("EqualSid").Call(uintptr(unsafe.Pointer(actualIL.SID)), uintptr(unsafe.Pointer(ilSID)))
	if equal == 0 {
		return fmt.Errorf("child integrity verification failed")
	}
	actualUser, err := tokenInfo(actual, 1)
	if err != nil {
		return err
	}
	userAttrs := (*sidAttributes)(unsafe.Pointer(&actualUser[0]))
	if userAttrs.Attributes&0x10 == 0 || userAttrs.Attributes&4 != 0 {
		return fmt.Errorf("child user SID is not deny-only")
	}
	// Administrators can be absent for a standard account; if present it must be deny-only.
	if checkSID(original, 2, adminSID, false) == nil {
		if err := checkSID(actual, 2, adminSID, true); err != nil {
			return fmt.Errorf("Administrators deny-only: %w", err)
		}
	}
	if err := checkSID(actual, 11, everyoneSID, false); err != nil {
		return err
	}
	if err := checkSID(actual, 11, usersSID, false); err != nil {
		return err
	}
	if err := checkSID(actual, 11, restrictedSID, false); err != nil {
		return err
	}
	privs, err := tokenInfo(actual, 3)
	if err != nil {
		return err
	}
	privCount := *(*uint32)(unsafe.Pointer(&privs[0]))
	for i := uint32(0); i < privCount; i++ {
		// LUID_AND_ATTRIBUTES is 12 bytes; SeChangeNotifyPrivilege has LUID 23.
		offset := 4 + int(i)*12
		luid := *(*uint64)(unsafe.Pointer(&privs[offset]))
		attributes := *(*uint32)(unsafe.Pointer(&privs[offset+8]))
		if attributes&2 != 0 && luid != 23 {
			return fmt.Errorf("unexpected enabled privilege LUID %d", luid)
		}
	}
	var policy uint32
	if err := call(k32.NewProc("GetProcessMitigationPolicy"), uintptr(pi.Process), 4, uintptr(unsafe.Pointer(&policy)), 4); err != nil {
		return err
	}
	if policy&1 == 0 {
		return fmt.Errorf("win32k lockdown missing")
	}
	var inJob uint32
	if err := call(k32.NewProc("IsProcessInJob"), uintptr(pi.Process), job, uintptr(unsafe.Pointer(&inJob))); err != nil {
		return err
	}
	if inJob == 0 {
		return fmt.Errorf("child not in job")
	}
	fmt.Printf("Verified PID %d: restricted token, user deny-only, %s integrity, 3 restricting SIDs, win32k disabled, job UI=0xFF, process limit=1\n", pi.ProcessId, integrity)
	started := time.Now()
	resumed, _, lastErr := k32.NewProc("ResumeThread").Call(uintptr(pi.Thread))
	if uint32(resumed) == 0xFFFFFFFF {
		return fmt.Errorf("ResumeThread: %w", lastErr)
	}
	if _, err := syscall.WaitForSingleObject(pi.Process, syscall.INFINITE); err != nil {
		return err
	}
	finished = true
	var exit uint32
	if err := syscall.GetExitCodeProcess(pi.Process, &exit); err != nil {
		return err
	}
	fmt.Printf("Child exit: 0x%08X after %.2fs (includes Windows crash handling)\n", exit, time.Since(started).Seconds())
	if exit != 0xC0000005 {
		return fmt.Errorf("expected unhandled exception 0xC0000005")
	}
	return nil
}

func main() {
	integrity := flag.String("integrity", "low", "low or untrusted")
	flag.Parse()
	if err := run(*integrity); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
