#ifndef WINDOWS_ACL_MAP_STUB_H
#define WINDOWS_ACL_MAP_STUB_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define WINAPI
#define TRUE 1
#define MAX_PATH 260
#define FALSE 0
#define CP_UTF8 65001U
#define WC_ERR_INVALID_CHARS 0x80U
#define ERROR_SUCCESS 0U
#define ERROR_INSUFFICIENT_BUFFER 122U
#define ERROR_OUTOFMEMORY 14U
#define ERROR_CALL_NOT_IMPLEMENTED 120U
#define ERROR_INVALID_NAME 123U
#define ERROR_FILENAME_EXCED_RANGE 206U
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define TOKEN_QUERY 0x0008U
#define TOKEN_ADJUST_PRIVILEGES 0x0020U
#define SE_PRIVILEGE_ENABLED 0x00000002U
#define FILE_SHARE_READ 1U
#define FILE_SHARE_WRITE 2U
#define FILE_SHARE_DELETE 4U
#define OPEN_EXISTING 3U
#define CREATE_NEW 1U
#define FILE_ATTRIBUTE_NORMAL 0x80U
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000U
#define GENERIC_WRITE 0x40000000U
#define READ_CONTROL 0x00020000U
#define WRITE_DAC 0x00040000U
#define SE_FILE_OBJECT 1U
#define OWNER_SECURITY_INFORMATION 0x00000001U
#define GROUP_SECURITY_INFORMATION 0x00000002U
#define DACL_SECURITY_INFORMATION 0x00000004U
#define SACL_SECURITY_INFORMATION 0x00000008U
#define LABEL_SECURITY_INFORMATION 0x00000010U
#define ATTRIBUTE_SECURITY_INFORMATION 0x00000020U
#define SCOPE_SECURITY_INFORMATION 0x00000040U
#define PROCESS_TRUST_LABEL_SECURITY_INFORMATION 0x00000080U
#define ACCESS_FILTER_SECURITY_INFORMATION 0x00000100U
#define BACKUP_SECURITY_INFORMATION 0x00010000U
#define SE_SECURITY_NAME L"SeSecurityPrivilege"
#define SE_BACKUP_NAME L"SeBackupPrivilege"
#define SE_RESTORE_NAME L"SeRestorePrivilege"
#define SE_TAKE_OWNERSHIP_NAME L"SeTakeOwnershipPrivilege"
#define ZeroMemory(destination,length) memset((destination),0,(length))

typedef int BOOL;
typedef int errno_t;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef uint32_t ACCESS_MASK;
typedef uint32_t SECURITY_INFORMATION;
typedef wchar_t WCHAR;
typedef WCHAR *LPWSTR;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *PSID;
typedef void *PACL;
typedef void *PSECURITY_DESCRIPTOR;
typedef void (*FARPROC)(void);

typedef struct LARGE_INTEGER { int64_t QuadPart; } LARGE_INTEGER;
typedef struct LUID { DWORD LowPart; LONG HighPart; } LUID;
typedef struct LUID_AND_ATTRIBUTES { LUID Luid; DWORD Attributes; } LUID_AND_ATTRIBUTES;
typedef struct SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; } SID_AND_ATTRIBUTES;
typedef struct TOKEN_USER { SID_AND_ATTRIBUTES User; } TOKEN_USER;
typedef struct TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label; } TOKEN_MANDATORY_LABEL;
typedef struct TOKEN_ELEVATION { DWORD TokenIsElevated; } TOKEN_ELEVATION;
typedef struct TOKEN_GROUPS { DWORD GroupCount; SID_AND_ATTRIBUTES Groups[1]; } TOKEN_GROUPS;
typedef struct TOKEN_PRIVILEGES { DWORD PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[1]; } TOKEN_PRIVILEGES;
typedef struct SYSTEM_INFO { WORD wProcessorArchitecture; WORD reserved; DWORD page_size; void *minimum; void *maximum; uintptr_t mask; DWORD processors; DWORD type; DWORD granularity; WORD level; WORD revision; } SYSTEM_INFO;
typedef int TOKEN_INFORMATION_CLASS;
enum { TokenUser=1, TokenGroups=2, TokenPrivileges=3, TokenElevation=20, TokenIntegrityLevel=25 };

int WideCharToMultiByte(unsigned int,DWORD,const WCHAR*,int,char*,int,const char*,BOOL*);
BOOL ConvertSidToStringSidW(PSID,WCHAR**);
BOOL GetTokenInformation(HANDLE,TOKEN_INFORMATION_CLASS,void*,DWORD,DWORD*);
DWORD GetLastError(void);
void SetLastError(DWORD);
BOOL LookupPrivilegeNameW(const WCHAR*,LUID*,WCHAR*,DWORD*);
BOOL LookupPrivilegeValueW(const WCHAR*,const WCHAR*,LUID*);
BOOL AdjustTokenPrivileges(HANDLE,BOOL,TOKEN_PRIVILEGES*,DWORD,TOKEN_PRIVILEGES*,DWORD*);
BOOL GetVolumePathNameW(const WCHAR*,WCHAR*,DWORD);
BOOL GetVolumeInformationW(const WCHAR*,WCHAR*,DWORD,DWORD*,DWORD*,DWORD*,WCHAR*,DWORD);
void GetNativeSystemInfo(SYSTEM_INFO*);
HMODULE GetModuleHandleW(const WCHAR*);
FARPROC GetProcAddress(HMODULE,const char*);
HANDLE CreateFileW(const WCHAR*,DWORD,DWORD,void*,DWORD,DWORD,HANDLE);
DWORD GetSecurityInfo(HANDLE,DWORD,SECURITY_INFORMATION,PSID*,PSID*,PACL*,PACL*,PSECURITY_DESCRIPTOR*);
DWORD SetSecurityInfo(HANDLE,DWORD,SECURITY_INFORMATION,PSID,PSID,PACL,PACL);
DWORD GetNamedSecurityInfoW(LPWSTR,DWORD,SECURITY_INFORMATION,PSID*,PSID*,PACL*,PACL*,PSECURITY_DESCRIPTOR*);
void *LocalFree(void*);
BOOL CloseHandle(HANDLE);
BOOL CreateDirectoryW(const WCHAR*,void*);
BOOL WriteFile(HANDLE,const void*,DWORD,DWORD*,void*);
BOOL SetFileAttributesW(const WCHAR*,DWORD);
BOOL DeleteFileW(const WCHAR*);
BOOL RemoveDirectoryW(const WCHAR*);
BOOL OpenProcessToken(HANDLE,DWORD,HANDLE*);
HANDLE GetCurrentProcess(void);
DWORD GetCurrentProcessId(void);
void QuerySecurityAccessMask(SECURITY_INFORMATION,DWORD*);
void SetSecurityAccessMask(SECURITY_INFORMATION,DWORD*);
int swprintf_s(WCHAR*,size_t,const WCHAR*,...);
errno_t _wfopen_s(FILE**,const WCHAR*,const WCHAR*);

#endif
