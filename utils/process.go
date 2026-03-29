package utils

import (
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modkernel32                     = syscall.NewLazyDLL("kernel32.dll")
	modiphlpapi                     = syscall.NewLazyDLL("iphlpapi.dll")
	procGetNamedPipeClientProcessId = modkernel32.NewProc("GetNamedPipeClientProcessId")
	procOpenProcess                 = modkernel32.NewProc("OpenProcess")
	procCloseHandle                 = modkernel32.NewProc("CloseHandle")
	procQueryFullProcessImageNameW  = modkernel32.NewProc("QueryFullProcessImageNameW")
	procCreateToolhelp32Snapshot    = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW             = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW              = modkernel32.NewProc("Process32NextW")
	procGetExtendedTcpTable         = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	TH32CS_SNAPPROCESS                = 0x00000002
	MAX_PATH                          = 260
	AF_INET                           = 2
	TCP_TABLE_OWNER_PID_CONNECTIONS   = 4
)

type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [MAX_PATH]uint16
}

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type mibTcpTableOwnerPid struct {
	NumEntries uint32
	Table      [1]mibTcpRowOwnerPid
}

func GetNamedPipeClientPID(handle uintptr) (uint32, error) {
	var pid uint32
	r1, _, err := procGetNamedPipeClientProcessId.Call(handle, uintptr(unsafe.Pointer(&pid)))
	if r1 == 0 {
		return 0, err
	}
	return pid, nil
}

// GetConnPID extracts the client PID from a net.Conn, supporting both
// TCP connections (via the TCP table) and pipe-backed connections (via handle).
func GetConnPID(conn net.Conn) uint32 {
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if localAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			pid, _ := GetTCPConnectionPID(uint16(localAddr.Port), uint16(tcpAddr.Port))
			return pid
		}
	}
	if fdConn, ok := conn.(interface{ Fd() uintptr }); ok {
		pid, _ := GetNamedPipeClientPID(fdConn.Fd())
		return pid
	}
	return 0
}

func GetProcessName(pid uint32) string {
	h, _, err := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if h == 0 {
		_ = err
		return ""
	}
	defer procCloseHandle.Call(h)

	var buf [MAX_PATH]uint16
	size := uint32(MAX_PATH)
	r1, _, _ := procQueryFullProcessImageNameW.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r1 == 0 {
		return ""
	}
	return filepath.Base(syscall.UTF16ToString(buf[:size]))
}

func GetTCPConnectionPID(localPort, remotePort uint16) (uint32, error) {
	var size uint32
	// First call to get required buffer size
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)

	buf := make([]byte, size)
	r1, _, err := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		TCP_TABLE_OWNER_PID_CONNECTIONS,
		0,
	)
	if r1 != 0 {
		return 0, err
	}

	table := (*mibTcpTableOwnerPid)(unsafe.Pointer(&buf[0]))
	rows := (*[1 << 16]mibTcpRowOwnerPid)(unsafe.Pointer(&table.Table[0]))[:table.NumEntries:table.NumEntries]

	// Port values in the table are in network byte order (big-endian)
	wantLocal := uint32(localPort)<<8 | uint32(localPort)>>8
	wantRemote := uint32(remotePort)<<8 | uint32(remotePort)>>8

	for _, row := range rows {
		if row.LocalPort == wantLocal && row.RemotePort == wantRemote {
			return row.OwningPid, nil
		}
	}
	return 0, syscall.ENOENT
}

// GetProcessChain walks the parent process tree and returns a string like
// "git.exe > devenv.exe" (target process first, ancestors last).
func GetProcessChain(pid uint32) string {
	// Build a map of pid -> (parentPid, name) from the process snapshot
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == ^uintptr(0) { // INVALID_HANDLE_VALUE
		_ = err
		name := GetProcessName(pid)
		if name == "" {
			return ""
		}
		return name
	}
	defer procCloseHandle.Call(snapshot)

	type procInfo struct {
		parentPID uint32
		name      string
	}
	procs := make(map[uint32]procInfo)

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	r1, _, _ := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return GetProcessName(pid)
	}

	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		procs[entry.ProcessID] = procInfo{parentPID: entry.ParentProcessID, name: name}

		entry.Size = uint32(unsafe.Sizeof(entry))
		r1, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if r1 == 0 {
			break
		}
	}

	// Walk up from pid to root
	var chain []string
	seen := make(map[uint32]bool)
	cur := pid
	for {
		if seen[cur] {
			break // cycle
		}
		seen[cur] = true
		info, ok := procs[cur]
		if !ok || cur == 0 {
			break
		}
		chain = append(chain, info.name)
		cur = info.parentPID
	}

	if len(chain) == 0 {
		return ""
	}

	// Trim common root processes
	rootsToTrim := map[string]bool{
		"explorer.exe": true,
		"svchost.exe":  true,
		"services.exe": true,
		"System":       true,
		"wininit.exe":  true,
		"csrss.exe":    true,
		"smss.exe":     true,
		"lsass.exe":    true,
		"winlogon.exe": true,
		"sihost.exe":   true,
	}

	// chain is [target, parent, grandparent, ...] — trim root ancestors from the end
	for len(chain) > 1 && rootsToTrim[strings.ToLower(chain[len(chain)-1])] {
		chain = chain[:len(chain)-1]
	}

	// Remove consecutive duplicates
	deduped := chain[:1]
	for _, name := range chain[1:] {
		if name != deduped[len(deduped)-1] {
			deduped = append(deduped, name)
		}
	}

	// hide ssh.exe/ssh-keygen.exe when it is a child process of git.exe
	if len(deduped) >= 2 && deduped[1] == "git.exe" && (deduped[0] == "ssh-keygen.exe" || deduped[0] == "ssh.exe") {
		deduped = deduped[1:]
	}

	return strings.Join(deduped, " > ")
}
