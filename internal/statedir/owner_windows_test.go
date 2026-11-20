//go:build windows

package statedir

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestDirectoryACEAddsSubdirExplicitly 验证 ProgramData 默认继承的 Users:(CI)(AD)
// 不会被误判为不安全，同时显式 ADD_SUBDIRECTORY 与真正可写文件/改 ACL 的权限仍会触发拒绝。
func TestDirectoryACEAddsSubdirExplicitly(t *testing.T) {
	cases := []struct {
		name     string
		mask     windows.ACCESS_MASK
		aceFlags uint8
		want     bool
	}{
		{"继承的 ADD_SUBDIRECTORY 放行", windows.FILE_APPEND_DATA, windows.CONTAINER_INHERIT_ACE | windows.INHERITED_ACE, false},
		{"显式 ADD_SUBDIRECTORY 拒绝", windows.FILE_APPEND_DATA, windows.CONTAINER_INHERIT_ACE, true},
		{"无 ADD_SUBDIRECTORY", windows.FILE_LIST_DIRECTORY, windows.INHERITED_ACE, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := directoryACEAddsSubdirExplicitly(tc.mask, tc.aceFlags); got != tc.want {
				t.Fatalf("directoryACEAddsSubdirExplicitly(%#x, %#x) = %v，期望 %v", tc.mask, tc.aceFlags, got, tc.want)
			}
			// 主掩码中的权限不受继承标志影响，始终应被 checkDirDACL 视为可写风险。
			if risky := tc.mask&windowsDACLWriteMask != 0; risky && tc.mask == windows.FILE_LIST_DIRECTORY {
				t.Fatalf("只读权限不应命中写掩码")
			}
		})
	}
	if windowsDACLWriteMask&windows.FILE_APPEND_DATA != 0 {
		t.Fatal("windowsDACLWriteMask 不应包含 FILE_APPEND_DATA（目录上等于 ADD_SUBDIRECTORY）")
	}
	for _, bit := range []windows.ACCESS_MASK{
		windows.FILE_WRITE_DATA, winFileDeleteChild, windows.DELETE, windows.WRITE_DAC, windows.WRITE_OWNER,
		windows.GENERIC_WRITE, windows.GENERIC_ALL,
	} {
		if windowsDACLWriteMask&bit == 0 {
			t.Fatalf("windowsDACLWriteMask 应包含权限位 %#x", bit)
		}
	}
	if winFileDeleteChild != 0x40 {
		t.Fatalf("FILE_DELETE_CHILD 应为 0x40，实际 %#x", winFileDeleteChild)
	}
}

// TestNonGrantingACEType 验证只有确定不授予访问权的 ACE 类型会被跳过；
// ACCESS_ALLOWED_OBJECT_ACE_TYPE / callback / 未知类型必须 fail-closed。
func TestNonGrantingACEType(t *testing.T) {
	cases := []struct {
		name    string
		aceType uint8
		want    bool
	}{
		{"ACCESS_DENIED_ACE_TYPE", windows.ACCESS_DENIED_ACE_TYPE, true},
		{"ACCESS_DENIED_OBJECT_ACE_TYPE", winAccessDeniedObjectACE, true},
		{"ACCESS_DENIED_CALLBACK_ACE_TYPE", winAccessDeniedCallbackACE, true},
		{"ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE", winAccessDeniedCallbackObjectACE, true},
		{"SYSTEM_AUDIT_ACE_TYPE", winSystemAuditACE, true},
		{"SYSTEM_MANDATORY_LABEL_ACE_TYPE", winSystemMandatoryLabelACE, true},
		{"ACCESS_ALLOWED_ACE_TYPE 需由调用方按普通 ACE 检查", windows.ACCESS_ALLOWED_ACE_TYPE, false},
		{"ACCESS_ALLOWED_OBJECT_ACE_TYPE 必须 fail-closed", winAccessAllowedObjectACE, false},
		{"ACCESS_ALLOWED_CALLBACK_ACE_TYPE 必须 fail-closed", winAccessAllowedCallbackACE, false},
		{"ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE 必须 fail-closed", winAccessAllowedCallbackObjectACE, false},
		{"未知 ACE 类型必须 fail-closed", 0xff, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nonGrantingACEType(tc.aceType); got != tc.want {
				t.Fatalf("nonGrantingACEType(%d) = %v，期望 %v", tc.aceType, got, tc.want)
			}
		})
	}
}
