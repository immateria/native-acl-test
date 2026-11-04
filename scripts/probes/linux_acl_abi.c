#include <acl/libacl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/acl.h>
#include <sys/types.h>

int main(void) {
    printf("sizeof(acl_type_t)=%zu signed=%d\n", sizeof(acl_type_t), ((acl_type_t)-1) < 0);
    printf("sizeof(acl_tag_t)=%zu signed=%d\n", sizeof(acl_tag_t), ((acl_tag_t)-1) < 0);
    printf("sizeof(acl_perm_t)=%zu signed=%d\n", sizeof(acl_perm_t), ((acl_perm_t)-1) < 0);
    printf("sizeof(uid_t)=%zu signed=%d\n", sizeof(uid_t), ((uid_t)-1) < 0);
    printf("sizeof(gid_t)=%zu signed=%d\n", sizeof(gid_t), ((gid_t)-1) < 0);
    printf("ACL_TYPE_ACCESS=%#x ACL_TYPE_DEFAULT=%#x\n", ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT);
    printf("ACL_READ=%#x ACL_WRITE=%#x ACL_EXECUTE=%#x\n", ACL_READ, ACL_WRITE, ACL_EXECUTE);
    return 0;
}
