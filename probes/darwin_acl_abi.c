/* Native SDK/oracle probe, not executed on Linux. No filesystem ACL changes. */
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

_Static_assert(sizeof(struct attrlist) == 24, "attrlist ABI changed");
_Static_assert(sizeof(attrreference_t) == 8, "attrreference ABI changed");
_Static_assert(ATTR_CMN_EXTENDED_SECURITY == 0x00400000, "ACL attribute changed");
_Static_assert(ATTR_CMN_RETURNED_ATTRS == 0x80000000, "returned bitmap changed");
_Static_assert(FSOPT_REPORT_FULLSIZE == 4, "full-size option changed");
_Static_assert(sizeof(acl_type_t) == 4, "acl_type_t ABI changed");
_Static_assert(ACL_TYPE_EXTENDED == 0x100, "extended ACL type changed");
_Static_assert(ACL_MAX_ENTRIES == 128, "entry bound changed");
_Static_assert(O_SYMLINK == 0x00200000, "O_SYMLINK changed");
_Static_assert(O_CLOEXEC == 0x01000000, "O_CLOEXEC changed");
_Static_assert(O_NONBLOCK == 4, "O_NONBLOCK changed");

_Static_assert(ACL_READ_DATA == 2, "ACL_READ_DATA changed");
_Static_assert(ACL_WRITE_DATA == 4, "ACL_WRITE_DATA changed");
_Static_assert(ACL_EXECUTE == 8, "ACL_EXECUTE changed");
_Static_assert(ACL_DELETE == 16, "ACL_DELETE changed");
_Static_assert(ACL_APPEND_DATA == 32, "ACL_APPEND_DATA changed");
_Static_assert(ACL_DELETE_CHILD == 64, "ACL_DELETE_CHILD changed");
_Static_assert(ACL_READ_ATTRIBUTES == 128, "ACL_READ_ATTRIBUTES changed");
_Static_assert(ACL_WRITE_ATTRIBUTES == 256, "ACL_WRITE_ATTRIBUTES changed");
_Static_assert(ACL_READ_EXTATTRIBUTES == 512, "ACL_READ_EXTATTRIBUTES changed");
_Static_assert(ACL_WRITE_EXTATTRIBUTES == 1024, "ACL_WRITE_EXTATTRIBUTES changed");
_Static_assert(ACL_READ_SECURITY == 2048, "ACL_READ_SECURITY changed");
_Static_assert(ACL_WRITE_SECURITY == 4096, "ACL_WRITE_SECURITY changed");
_Static_assert(ACL_CHANGE_OWNER == 8192, "ACL_CHANGE_OWNER changed");
_Static_assert(ACL_SYNCHRONIZE == 1048576, "ACL_SYNCHRONIZE changed");
_Static_assert(ACL_ENTRY_INHERITED == 16, "ACL_ENTRY_INHERITED changed");
_Static_assert(ACL_ENTRY_FILE_INHERIT == 32, "ACL_ENTRY_FILE_INHERIT changed");
_Static_assert(ACL_ENTRY_DIRECTORY_INHERIT == 64, "ACL_ENTRY_DIRECTORY_INHERIT changed");
_Static_assert(ACL_ENTRY_LIMIT_INHERIT == 128, "ACL_ENTRY_LIMIT_INHERIT changed");
_Static_assert(ACL_ENTRY_ONLY_INHERIT == 256, "ACL_ENTRY_ONLY_INHERIT changed");
_Static_assert(ACL_FLAG_NO_INHERIT == 131072, "ACL_FLAG_NO_INHERIT changed");
_Static_assert(ACL_FLAG_DEFER_INHERIT == 1, "ACL_FLAG_DEFER_INHERIT changed");
_Static_assert(KAUTH_ACL_DEFER_INHERIT == 65536, "KAUTH_ACL_DEFER_INHERIT changed");

static void check(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "%s failed (errno=%d)\n", operation, errno);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        struct statfs fs;
        check(statfs(argv[1], &fs) == 0, "statfs");
        printf("filesystem=%s flags=0x%lx\n", fs.f_fstypename, (unsigned long)fs.f_flags);
    }
    const unsigned char uuid[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    acl_t acl = acl_init(1);
    check(acl != NULL, "acl_init");
    acl_entry_t entry;
    acl_permset_t permissions;
    check(acl_create_entry(&acl, &entry) == 0, "acl_create_entry");
    check(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0, "acl_set_tag_type");
    check(acl_set_qualifier(entry, uuid) == 0, "acl_set_qualifier");
    check(acl_get_permset(entry, &permissions) == 0, "acl_get_permset");
    check(acl_add_perm(permissions, ACL_READ_DATA) == 0, "acl_add_perm");
    check(acl_set_permset(entry, permissions) == 0, "acl_set_permset");
    unsigned char exported[68];
    unsigned char expected[68] = {0};
    expected[0] = 0x01; expected[1] = 0x2c;
    expected[2] = 0xc1; expected[3] = 0x6d;
    expected[39] = 1; /* BE entry count */
    memcpy(expected + 44, uuid, sizeof(uuid));
    expected[63] = 1; /* allow */
    expected[67] = 2; /* read data */
    check(acl_size(acl) == (ssize_t)sizeof(exported), "44+24n export length");
    check(acl_copy_ext(exported, acl, sizeof(exported)) == (ssize_t)sizeof(exported), "acl_copy_ext");
    check(memcmp(expected, exported, sizeof(expected)) == 0, "Crystal golden export matches native libc");
    acl_t copy = acl_copy_int(exported);
    check(copy != NULL, "acl_copy_int");
    check(acl_get_entry(copy, ACL_FIRST_ENTRY, &entry) == 0, "entry success is zero");
    errno = 0;
    check(acl_get_entry(copy, ACL_NEXT_ENTRY, &entry) == -1 && errno == EINVAL,
          "entry exhaustion is -1/EINVAL");
    acl_free(copy);
    acl_free(acl);
    printf("Darwin export/iterator/attribute ABI: pass; attrlist=%zu reference=%zu\n",
           sizeof(struct attrlist), sizeof(attrreference_t));
    return EXIT_SUCCESS;
}
