/* Native SDK/oracle probe, not executed on Linux. No filesystem ACL changes. */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <lm.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(DWORD) == 4, "DWORD ABI changed");
_Static_assert(sizeof(BOOL) == 4, "BOOL ABI changed");
_Static_assert(sizeof(ACL) == 8, "ACL ABI changed");
_Static_assert(sizeof(ACE_HEADER) == 4, "ACE_HEADER ABI changed");
_Static_assert(sizeof(SECURITY_DESCRIPTOR_RELATIVE) == 20, "relative descriptor ABI changed");
_Static_assert(sizeof(GUID) == 16, "GUID ABI changed");
_Static_assert(offsetof(SID, SubAuthority) == 8, "SID layout changed");
_Static_assert(offsetof(SECURITY_DESCRIPTOR_RELATIVE, Dacl) == 16, "DACL offset changed");

_Static_assert(sizeof(void *) == 8, "test kit supports 64-bit Windows targets");
_Static_assert(sizeof(LUID) == 8, "LUID ABI changed");
_Static_assert(sizeof(LUID_AND_ATTRIBUTES) == 12, "LUID_AND_ATTRIBUTES ABI changed");
_Static_assert(sizeof(SID_AND_ATTRIBUTES) == 16, "SID_AND_ATTRIBUTES ABI changed");
_Static_assert(sizeof(TOKEN_MANDATORY_LABEL) == 16, "TOKEN_MANDATORY_LABEL ABI changed");
_Static_assert(sizeof(PROCESS_INFORMATION) == 24, "PROCESS_INFORMATION ABI changed");
_Static_assert(sizeof(STARTUPINFOW) == 104, "STARTUPINFOW ABI changed");
_Static_assert(offsetof(STARTUPINFOW, hStdInput) == 80, "STARTUPINFOW stdio offset changed");
_Static_assert(offsetof(STARTUPINFOW, hStdOutput) == 88, "STARTUPINFOW stdout offset changed");
_Static_assert(offsetof(STARTUPINFOW, hStdError) == 96, "STARTUPINFOW stderr offset changed");
_Static_assert(offsetof(USER_INFO_1, usri1_password) == sizeof(void *), "USER_INFO_1 pointer layout changed");
_Static_assert(sizeof(LOCALGROUP_MEMBERS_INFO_3) == sizeof(void *), "LOCALGROUP_MEMBERS_INFO_3 ABI changed");

_Static_assert(LOGON32_LOGON_INTERACTIVE == 2, "interactive logon constant changed");
_Static_assert(DISABLE_MAX_PRIVILEGE == 1, "restricted-token flag changed");
_Static_assert(SE_GROUP_USE_FOR_DENY_ONLY == 0x10, "deny-only group flag changed");
_Static_assert(SE_GROUP_INTEGRITY == 0x20, "integrity group flag changed");
_Static_assert(SE_GROUP_INTEGRITY_ENABLED == 0x40, "integrity-enabled flag changed");
_Static_assert(TokenIntegrityLevel == 25, "TOKEN_INFORMATION_CLASS value changed");
_Static_assert(OWNER_SECURITY_INFORMATION == 0x1, "owner selector changed");
_Static_assert(GROUP_SECURITY_INFORMATION == 0x2, "group selector changed");
_Static_assert(DACL_SECURITY_INFORMATION == 0x4, "DACL selector changed");
_Static_assert(SACL_SECURITY_INFORMATION == 0x8, "SACL selector changed");
_Static_assert(LABEL_SECURITY_INFORMATION == 0x10, "label selector changed");
_Static_assert(ATTRIBUTE_SECURITY_INFORMATION == 0x20, "attribute selector changed");
_Static_assert(SCOPE_SECURITY_INFORMATION == 0x40, "scope selector changed");
_Static_assert(PROCESS_TRUST_LABEL_SECURITY_INFORMATION == 0x80, "process trust selector changed");
_Static_assert(ACCESS_FILTER_SECURITY_INFORMATION == 0x100, "access filter selector changed");
_Static_assert(BACKUP_SECURITY_INFORMATION == 0x10000, "backup selector changed");

_Static_assert(ACCESS_ALLOWED_ACE_TYPE == 0, "allow ACE type changed");
_Static_assert(ACCESS_DENIED_ACE_TYPE == 1, "deny ACE type changed");
_Static_assert(SYSTEM_AUDIT_ACE_TYPE == 2, "audit ACE type changed");
_Static_assert(ACCESS_ALLOWED_COMPOUND_ACE_TYPE == 4, "compound ACE type changed");
_Static_assert(SYSTEM_MANDATORY_LABEL_ACE_TYPE == 17, "mandatory label ACE type changed");
_Static_assert(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE == 18, "resource attribute ACE type changed");
_Static_assert(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE == 19, "scope ACE type changed");
_Static_assert(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE == 20, "process trust ACE type changed");
_Static_assert(SYSTEM_ACCESS_FILTER_ACE_TYPE == 21, "access filter ACE type changed");

_Static_assert(READ_CONTROL == 0x20000, "READ_CONTROL changed");
_Static_assert(WRITE_DAC == 0x40000, "WRITE_DAC changed");
_Static_assert(WRITE_OWNER == 0x80000, "WRITE_OWNER changed");
_Static_assert(SYNCHRONIZE == 0x100000, "SYNCHRONIZE changed");
_Static_assert(OBJECT_INHERIT_ACE == 1, "OBJECT_INHERIT_ACE changed");
_Static_assert(CONTAINER_INHERIT_ACE == 2, "CONTAINER_INHERIT_ACE changed");
_Static_assert(NO_PROPAGATE_INHERIT_ACE == 4, "NO_PROPAGATE_INHERIT_ACE changed");
_Static_assert(INHERIT_ONLY_ACE == 8, "INHERIT_ONLY_ACE changed");
_Static_assert(INHERITED_ACE == 16, "INHERITED_ACE changed");
_Static_assert(SUCCESSFUL_ACCESS_ACE_FLAG == 64, "SUCCESSFUL_ACCESS_ACE_FLAG changed");
_Static_assert(FAILED_ACCESS_ACE_FLAG == 128, "FAILED_ACCESS_ACE_FLAG changed");
_Static_assert(SE_DACL_PROTECTED == 0x1000, "SE_DACL_PROTECTED changed");
_Static_assert(SE_SACL_PROTECTED == 0x2000, "SE_SACL_PROTECTED changed");
_Static_assert(SE_SELF_RELATIVE == 0x8000, "SE_SELF_RELATIVE changed");

static void check(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "%s failed (GetLastError=%lu)\n", operation, (unsigned long)GetLastError());
        exit(EXIT_FAILURE);
    }
}

int main(void) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL dacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    void *ace = NULL;
    const unsigned char expected_guid[16] = {
        0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:(OA;;GR;00112233-4455-6677-8899-aabbccddeeff;;WD)",
          SDDL_REVISION_1, &descriptor, NULL), "SDDL object ACE");
    check(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted), "get DACL");
    check(present && dacl != NULL && dacl->AclRevision == ACL_REVISION_DS, "object ACL revision");
    check(GetAce(dacl, 0, &ace), "GetAce");
    check(((ACE_HEADER *)ace)->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE, "object type");
    check(((ACE_HEADER *)ace)->AceSize == 40, "object ACE variable layout");
    check(memcmp((unsigned char *)ace + 12, expected_guid, 16) == 0, "mixed-endian GUID");
    check(IsValidSid((unsigned char *)ace + 28), "object SID offset");
    check(GetLengthSid((unsigned char *)ace + 28) == 12, "world SID length");
    LocalFree(descriptor);
    descriptor = NULL;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:NO_ACCESS_CONTROL", SDDL_REVISION_1, &descriptor, NULL), "null DACL SDDL");
    check(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted), "get null DACL");
    check(present && dacl == NULL, "null is present without ACL storage");
    LocalFree(descriptor);
    descriptor = NULL;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:", SDDL_REVISION_1, &descriptor, NULL), "empty DACL SDDL");
    check(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted), "get empty DACL");
    check(present && dacl != NULL && dacl->AceCount == 0, "empty is present ACL storage");
    LocalFree(descriptor);
    puts("Windows descriptor/SID/object ACE/null-empty/local-account/token ABI: pass");
    return EXIT_SUCCESS;
}
