/* Native SDK/oracle probe, not executed on Linux. No filesystem ACL changes. */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
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
    puts("Windows descriptor/SID/object ACE/null-empty ABI: pass");
    return EXIT_SUCCESS;
}
