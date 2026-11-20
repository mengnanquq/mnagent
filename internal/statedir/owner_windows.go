//go:build windows

package statedir

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FILE_DELETE_CHILD 在 golang.org/x/sys/windows 中未导出（值见 WinNT.h），
// 目录上的该权限允许删除目录内的文件，必须与写权限一起拒绝。
const winFileDeleteChild = windows.ACCESS_MASK(0x40)

// 非普通 ACE 类型（WinNT.h）。x/sys/windows 只导出了 ACCESS_ALLOWED_ACE_TYPE /
// ACCESS_DENIED_ACE_TYPE，这里补齐分类所需常量。
const (
	winAccessAllowedObjectACE         = 5
	winAccessAllowedCallbackACE       = 9
	winAccessAllowedCallbackObjectACE = 11
	winAccessDeniedObjectACE          = 6
	winAccessDeniedCallbackACE        = 10
	winAccessDeniedCallbackObjectACE  = 12
	winSystemAuditACE                 = 2
	winSystemAlarmACE                 = 3
	winSystemMandatoryLabelACE        = 0x11
	winSystemResourceAttributeACE     = 0x12
	winSystemScopedPolicyIDACE        = 0x13
)

// windowsDACLWriteMask 是“可写入/可替换文件/可改权限”的权限位集合：
// 只要宽泛组（Everyone / Authenticated Users / Users）持有其中任意一位，
// 该目录就不再是私有状态目录——普通用户可替换跳过版本记录、写入降级依赖。
//
// 注意 FILE_APPEND_DATA 在目录上等价于 FILE_ADD_SUBDIRECTORY（只能建子目录、不能建文件），
// 不放进主掩码：ProgramData 默认会给 Users 继承 (CI)(AD)，若一并拒绝会把
// 正常的系统级目录误判为不安全并静默退回用户缓存目录。显式（非继承）授予的
// ADD_SUBDIRECTORY 仍然拒绝，见 checkDirDACL。
const windowsDACLWriteMask = windows.ACCESS_MASK(windows.GENERIC_WRITE |
	windows.GENERIC_ALL |
	windows.FILE_WRITE_DATA |
	winFileDeleteChild |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER)

// icaclsFixHint 返回可直接复制执行的 ACL 收紧命令，供错误/告警展示。
func icaclsFixHint(dir string) string {
	return fmt.Sprintf("可执行 icacls \"%s\" /inheritance:r /grant:r \"SYSTEM:(OI)(CI)F\" \"Administrators:(OI)(CI)F\" 收紧", dir)
}

// checkDirOwner 在 Windows 上检查状态目录属主是否为 SYSTEM、Administrators
// 或当前用户。ProgramData 下的系统级目录通常属于 SYSTEM/Administrators；
// 非特权运行时回退到用户缓存目录，因此也允许当前用户拥有。
// 拒绝其他普通用户拥有的目录，避免其替换跳过版本记录等状态文件。
func checkDirOwner(dir string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("读取 %s 的安全描述符失败：%w；%s", dir, err, icaclsFixHint(dir))
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("无法确定 %s 的属主：%w；%s", dir, err, icaclsFixHint(dir))
	}

	allowed := make([]*windows.SID, 0, 3)
	for _, sidType := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
	} {
		if sid, sidErr := windows.CreateWellKnownSid(sidType); sidErr == nil {
			allowed = append(allowed, sid)
		}
	}
	if tokenUser, tokenErr := windows.GetCurrentProcessToken().GetTokenUser(); tokenErr == nil && tokenUser.User.Sid != nil {
		allowed = append(allowed, tokenUser.User.Sid)
	}
	for _, sid := range allowed {
		if owner.Equals(sid) {
			return checkDirDACL(dir)
		}
	}
	return fmt.Errorf("%s 属主既不是 SYSTEM / Administrators 也不是当前用户，拒绝使用；%s", dir, icaclsFixHint(dir))
}

// checkDirDACL 拒绝把 Everyone / Authenticated Users / Users 等宽泛组授予写权限
// 的目录（Windows 没有 POSIX 权限位，等价检查只能看 DACL）：
// 只要这些组能写入或修改 ACL，任何本地用户都能替换状态文件。
func checkDirDACL(dir string) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("读取 %s 的 DACL 失败：%w；%s", dir, err, icaclsFixHint(dir))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("读取 %s 的 DACL 失败：%w；%s", dir, err, icaclsFixHint(dir))
	}
	if dacl == nil {
		// 没有 DACL 表示所有人都拥有完全控制。
		return fmt.Errorf("%s 没有 DACL（等同于所有人可写），拒绝使用；%s", dir, icaclsFixHint(dir))
	}

	broadSIDs := make([]*windows.SID, 0, 3)
	for _, sidType := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,             // Everyone
		windows.WinAuthenticatedUserSid, // NT AUTHORITY\Authenticated Users
		windows.WinBuiltinUsersSid,      // BUILTIN\Users
	} {
		if sid, sidErr := windows.CreateWellKnownSid(sidType); sidErr == nil {
			broadSIDs = append(broadSIDs, sid)
		}
	}

	aceCount := uint32(dacl.AceCount)
	for i := uint32(0); i < aceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			// 无法解析的 ACE 不能当成安全：宁可拒绝使用状态目录。
			return fmt.Errorf("解析 %s 的第 %d 条 ACE 失败，拒绝使用；%s", dir, i, icaclsFixHint(dir))
		}
		// 只关心允许访问的 ACE；拒绝/审计类 ACE 不会授予权限，可以跳过。
		// 对象 ACE、callback ACE 及未知类型的 SID 偏移与 ACCESS_ALLOWED_ACE 不同，
		// 既无法按当前结构安全取出 SID，也可能是允许 ACE，因此 fail-closed。
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			if nonGrantingACEType(ace.Header.AceType) {
				continue
			}
			return fmt.Errorf("%s 的第 %d 条 ACE 类型为 %d（非普通允许 ACE），无法安全解析，拒绝使用；%s", dir, i, ace.Header.AceType, icaclsFixHint(dir))
		}
		if ace.Mask&windowsDACLWriteMask == 0 {
			// 仅继承的 ADD_SUBDIRECTORY 不构成替换状态文件的风险，放行；
			// 显式授予的 ADD_SUBDIRECTORY 仍可能被滥用（例如预置恶意子目录），拒绝。
			if !directoryACEAddsSubdirExplicitly(ace.Mask, ace.Header.AceFlags) {
				continue
			}
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, broad := range broadSIDs {
			if sid.Equals(broad) {
				return fmt.Errorf("%s 的 DACL 允许 Everyone / Authenticated Users / Users 写入，拒绝使用（%s）", dir, icaclsFixHint(dir))
			}
		}
	}
	return nil
}

// nonGrantingACEType 判断 ACE 类型是否确定不会授予访问权限，可以安全跳过。
// 除 ACCESS_DENIED_ACE_TYPE 外的拒绝/审计/强制标签等类型都不授予访问权；
// ACCESS_ALLOWED_OBJECT_ACE_TYPE（5）、callback/未知类型返回 false，由调用方 fail-closed。
func nonGrantingACEType(aceType uint8) bool {
	switch aceType {
	case windows.ACCESS_DENIED_ACE_TYPE,
		winAccessDeniedObjectACE,
		winAccessDeniedCallbackACE,
		winAccessDeniedCallbackObjectACE,
		winSystemAuditACE,
		winSystemAlarmACE,
		winSystemMandatoryLabelACE,
		winSystemResourceAttributeACE,
		winSystemScopedPolicyIDACE:
		return true
	}
	return false
}

// directoryACEAddsSubdirExplicitly 判断一条 ACE 是否通过 ADD_SUBDIRECTORY（FILE_APPEND_DATA）
// 显式授予创建子目录权限。继承来的 (CI)(AD) 常见于 ProgramData 默认 ACL，不视为风险。
func directoryACEAddsSubdirExplicitly(mask windows.ACCESS_MASK, aceFlags uint8) bool {
	return mask&windows.FILE_APPEND_DATA != 0 && aceFlags&windows.INHERITED_ACE == 0
}

// isCurrentUserOwner 在 Windows 上不使用 POSIX 权限位，无需收紧目录权限。
func isCurrentUserOwner(os.FileInfo) bool {
	return false
}
