//go:build windows

package statedir

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// checkDirOwner 在 Windows 上检查状态目录属主是否为 SYSTEM、Administrators
// 或当前用户。ProgramData 下的系统级目录通常属于 SYSTEM/Administrators；
// 非特权运行时回退到用户缓存目录，因此也允许当前用户拥有。
// 拒绝其他普通用户拥有的目录，避免其替换跳过版本记录等状态文件。
func checkDirOwner(dir string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("读取 %s 的安全描述符失败：%w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("无法确定 %s 的属主：%w", dir, err)
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
			return nil
		}
	}
	return fmt.Errorf("%s 属主既不是 SYSTEM / Administrators 也不是当前用户，拒绝使用", dir)
}

// isCurrentUserOwner 在 Windows 上不使用 POSIX 权限位，无需收紧目录权限。
func isCurrentUserOwner(os.FileInfo) bool {
	return false
}
