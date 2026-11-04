/*
 * Native Windows filesystem-security mapper.
 *
 * This executable is an independent SDK oracle. It creates only synthetic
 * fixtures below the caller-provided scratch root and emits JSONL evidence.
 * Individual Win32 failures are data; only fatal setup/output failures produce
 * a nonzero process status.
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifdef ACL_MAP_PORTABLE_STUB
#include "windows_acl_map_stub.h"
#else
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64 12
#endif

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define MAP_PATH_CAPACITY 32768
#define MAX_TOKEN_ITEMS 4096U

typedef LONG (WINAPI *RtlGetVersionFn)(void *);
typedef LONG (WINAPI *NtQueryObjectFn)(HANDLE, ULONG, void *, ULONG, ULONG *);

_Static_assert(sizeof(FARPROC) == sizeof(RtlGetVersionFn), "function pointer ABI mismatch");
_Static_assert(sizeof(FARPROC) == sizeof(NtQueryObjectFn), "function pointer ABI mismatch");

typedef struct RtlVersionInfoLocal {
    ULONG size;
    ULONG major;
    ULONG minor;
    ULONG build;
    ULONG platform;
    WCHAR service_pack[128];
} RtlVersionInfoLocal;

typedef struct ObjectBasicInformationLocal {
    ULONG attributes;
    ACCESS_MASK granted_access;
    ULONG handle_count;
    ULONG pointer_count;
    ULONG paged_pool_charge;
    ULONG nonpaged_pool_charge;
    ULONG reserved[3];
    ULONG name_info_size;
    ULONG type_info_size;
    ULONG security_descriptor_size;
    LARGE_INTEGER creation_time;
} ObjectBasicInformationLocal;

typedef struct Selector {
    const char *name;
    SECURITY_INFORMATION information;
} Selector;

typedef struct Variant {
    const char *name;
    DWORD access;
} Variant;

static FILE *output_file = NULL;
static NtQueryObjectFn nt_query_object = NULL;

static void json_bytes(FILE *stream, const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    fputc('"', stream);
    while (*cursor != 0U) {
        unsigned char value = *cursor++;
        switch (value) {
        case '"': fputs("\\\"", stream); break;
        case '\\': fputs("\\\\", stream); break;
        case '\b': fputs("\\b", stream); break;
        case '\f': fputs("\\f", stream); break;
        case '\n': fputs("\\n", stream); break;
        case '\r': fputs("\\r", stream); break;
        case '\t': fputs("\\t", stream); break;
        default:
            if (value < 0x20U) {
                fprintf(stream, "\\u%04x", (unsigned int)value);
            } else {
                fputc((int)value, stream);
            }
            break;
        }
    }
    fputc('"', stream);
}

static void json_wide(FILE *stream, const WCHAR *text) {
    int length;
    char *utf8;
    if (text == NULL) {
        fputs("null", stream);
        return;
    }
    length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, NULL, 0, NULL, NULL);
    if (length <= 0) {
        fputs("null", stream);
        return;
    }
    utf8 = (char *)malloc((size_t)length);
    if (utf8 == NULL) {
        fputs("null", stream);
        return;
    }
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, utf8, length, NULL, NULL) <= 0) {
        free(utf8);
        fputs("null", stream);
        return;
    }
    json_bytes(stream, utf8);
    free(utf8);
}

static WCHAR *sid_string(PSID sid) {
    WCHAR *text = NULL;
    if (sid == NULL || !ConvertSidToStringSidW(sid, &text)) {
        return NULL;
    }
    return text;
}

static void emit_fatal(const char *operation, DWORD code) {
    if (output_file != NULL) {
        fputs("{\"kind\":\"fatal\",\"operation\":", output_file);
        json_bytes(output_file, operation);
        fprintf(output_file, ",\"code\":%lu}\n", (unsigned long)code);
        fflush(output_file);
    }
}

static void *token_information(HANDLE token, TOKEN_INFORMATION_CLASS kind, DWORD *size_out) {
    DWORD size = 0;
    BYTE *buffer;
    SetLastError(ERROR_SUCCESS);
    if (GetTokenInformation(token, kind, NULL, 0, &size)) {
        return NULL;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0U) {
        return NULL;
    }
    buffer = (BYTE *)malloc((size_t)size);
    if (buffer == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    if (!GetTokenInformation(token, kind, buffer, size, &size)) {
        free(buffer);
        return NULL;
    }
    *size_out = size;
    return buffer;
}

static void emit_token(HANDLE token) {
    DWORD size = 0;
    TOKEN_USER *user = (TOKEN_USER *)token_information(token, TokenUser, &size);
    TOKEN_MANDATORY_LABEL *integrity = (TOKEN_MANDATORY_LABEL *)token_information(token, TokenIntegrityLevel, &size);
    TOKEN_ELEVATION elevation;
    DWORD elevation_size = 0;
    WCHAR *user_text = user == NULL ? NULL : sid_string(user->User.Sid);
    WCHAR *integrity_text = integrity == NULL ? NULL : sid_string(integrity->Label.Sid);
    BOOL elevated = FALSE;

    ZeroMemory(&elevation, sizeof(elevation));
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &elevation_size)) {
        elevated = elevation.TokenIsElevated != 0U;
    }
    fputs("{\"kind\":\"token\",\"user_sid\":", output_file);
    json_wide(output_file, user_text);
    fputs(",\"integrity_sid\":", output_file);
    json_wide(output_file, integrity_text);
    fprintf(output_file, ",\"elevated\":%s}\n", elevated ? "true" : "false");
    if (user_text != NULL) LocalFree(user_text);
    if (integrity_text != NULL) LocalFree(integrity_text);
    free(user);
    free(integrity);

    {
        TOKEN_GROUPS *groups = (TOKEN_GROUPS *)token_information(token, TokenGroups, &size);
        if (groups != NULL && groups->GroupCount <= MAX_TOKEN_ITEMS) {
            DWORD index;
            for (index = 0; index < groups->GroupCount; ++index) {
                WCHAR *text = sid_string(groups->Groups[index].Sid);
                fputs("{\"kind\":\"token_group\",\"sid\":", output_file);
                json_wide(output_file, text);
                fprintf(output_file, ",\"attributes\":%lu}\n",
                        (unsigned long)groups->Groups[index].Attributes);
                if (text != NULL) LocalFree(text);
            }
        }
        free(groups);
    }

    {
        TOKEN_PRIVILEGES *privileges = (TOKEN_PRIVILEGES *)token_information(token, TokenPrivileges, &size);
        if (privileges != NULL && privileges->PrivilegeCount <= MAX_TOKEN_ITEMS) {
            DWORD index;
            for (index = 0; index < privileges->PrivilegeCount; ++index) {
                WCHAR name[128];
                DWORD name_size = (DWORD)ARRAY_COUNT(name);
                ZeroMemory(name, sizeof(name));
                BOOL named = LookupPrivilegeNameW(NULL, &privileges->Privileges[index].Luid, name, &name_size);
                fputs("{\"kind\":\"token_privilege\",\"name\":", output_file);
                json_wide(output_file, named ? name : NULL);
                fprintf(output_file, ",\"attributes\":%lu}\n",
                        (unsigned long)privileges->Privileges[index].Attributes);
            }
        }
        free(privileges);
    }
}

static DWORD enable_privilege(HANDLE token, const WCHAR *name) {
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        return GetLastError();
    }
    ZeroMemory(&privileges, sizeof(privileges));
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL)) {
        return GetLastError();
    }
    return GetLastError();
}

static void emit_privilege_enable(HANDLE token, const WCHAR *name) {
    DWORD code = enable_privilege(token, name);
    fputs("{\"kind\":\"privilege_enable\",\"name\":", output_file);
    json_wide(output_file, name);
    fprintf(output_file, ",\"privilege_code\":%lu}\n", (unsigned long)code);
}

static void emit_environment(const WCHAR *scratch_root) {
    WCHAR volume_path[MAX_PATH];
    WCHAR filesystem[MAX_PATH];
    DWORD serial = 0;
    DWORD max_component = 0;
    DWORD flags = 0;
    SYSTEM_INFO system_info;
    RtlVersionInfoLocal version;
    DWORD volume_code = ERROR_SUCCESS;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersionFn rtl_get_version = NULL;
    FARPROC rtl_proc = NULL;
    FARPROC query_proc = NULL;

    ZeroMemory(volume_path, sizeof(volume_path));
    ZeroMemory(filesystem, sizeof(filesystem));
    if (!GetVolumePathNameW(scratch_root, volume_path, (DWORD)ARRAY_COUNT(volume_path))) {
        volume_code = GetLastError();
    } else if (!GetVolumeInformationW(volume_path, NULL, 0, &serial, &max_component, &flags,
                                      filesystem, (DWORD)ARRAY_COUNT(filesystem))) {
        volume_code = GetLastError();
    }
    GetNativeSystemInfo(&system_info);
    ZeroMemory(&version, sizeof(version));
    version.size = sizeof(version);
    if (ntdll != NULL) {
        rtl_proc = GetProcAddress(ntdll, "RtlGetVersion");
        query_proc = GetProcAddress(ntdll, "NtQueryObject");
        if (rtl_proc != NULL) memcpy(&rtl_get_version, &rtl_proc, sizeof(rtl_get_version));
        if (query_proc != NULL) memcpy(&nt_query_object, &query_proc, sizeof(nt_query_object));
    }
    if (rtl_get_version != NULL) {
        (void)rtl_get_version(&version);
    }

    fputs("{\"kind\":\"environment\",\"schema_version\":1,\"os_major\":", output_file);
    fprintf(output_file, "%lu,\"os_minor\":%lu,\"os_build\":%lu,\"architecture\":%u,",
            (unsigned long)version.major, (unsigned long)version.minor,
            (unsigned long)version.build, (unsigned int)system_info.wProcessorArchitecture);
    fputs("\"volume_path\":", output_file);
    json_wide(output_file, volume_code == ERROR_SUCCESS ? volume_path : NULL);
    fputs(",\"filesystem\":", output_file);
    json_wide(output_file, volume_code == ERROR_SUCCESS ? filesystem : NULL);
    fprintf(output_file, ",\"volume_flags\":%lu,\"max_component\":%lu,\"volume_code\":%lu,",
            (unsigned long)flags, (unsigned long)max_component, (unsigned long)volume_code);
    fprintf(output_file, "\"nt_query_object\":%s}\n", nt_query_object != NULL ? "true" : "false");
}

static DWORD open_fixture(const WCHAR *path, BOOL directory, DWORD access, HANDLE *handle_out) {
    HANDLE handle = CreateFileW(path, access,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING,
                                directory ? FILE_FLAG_BACKUP_SEMANTICS : 0U, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        *handle_out = NULL;
        return GetLastError();
    }
    *handle_out = handle;
    return ERROR_SUCCESS;
}

static void query_granted_access(HANDLE handle, DWORD *status_out, DWORD *access_out) {
    ObjectBasicInformationLocal information;
    ULONG returned = 0;
    LONG status;
    *status_out = ERROR_CALL_NOT_IMPLEMENTED;
    *access_out = 0;
    if (nt_query_object == NULL) {
        return;
    }
    ZeroMemory(&information, sizeof(information));
    status = nt_query_object(handle, 0U, &information, (ULONG)sizeof(information), &returned);
    *status_out = (DWORD)status;
    if (status >= 0) {
        *access_out = information.granted_access;
    }
}

static DWORD source_descriptor(const WCHAR *path, SECURITY_INFORMATION information,
                               PSID *owner, PSID *group, PACL *dacl, PACL *sacl,
                               PSECURITY_DESCRIPTOR *descriptor) {
    *owner = NULL;
    *group = NULL;
    *dacl = NULL;
    *sacl = NULL;
    *descriptor = NULL;
    return GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, information,
                                 owner, group, dacl, sacl, descriptor);
}

static BOOL join_path(WCHAR *destination, size_t capacity, const WCHAR *parent, const WCHAR *child) {
    int result = swprintf_s(destination, capacity, L"%ls\\%ls", parent, child);
    return result > 0 && (size_t)result < capacity;
}

static DWORD create_attempt_fixture(const WCHAR *root, BOOL directory,
                                    unsigned long attempt_id, WCHAR *path) {
    WCHAR name[96];
    HANDLE file;
    DWORD written = 0;
    static const BYTE content[] = "acl native mapping fixture";
    int result = swprintf_s(name, ARRAY_COUNT(name),
                            directory ? L"directory-%06lu" : L"file-%06lu.bin",
                            attempt_id);
    if (result <= 0 || !join_path(path, MAP_PATH_CAPACITY, root, name)) {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    if (directory) {
        return CreateDirectoryW(path, NULL) ? ERROR_SUCCESS : GetLastError();
    }
    file = CreateFileW(path, GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    if (!WriteFile(file, content, (DWORD)(sizeof(content) - 1U), &written, NULL)) {
        DWORD code = GetLastError();
        CloseHandle(file);
        (void)DeleteFileW(path);
        return code;
    }
    CloseHandle(file);
    return ERROR_SUCCESS;
}

static DWORD cleanup_attempt_fixture(const WCHAR *path, BOOL directory) {
    if (directory) {
        return RemoveDirectoryW(path) ? ERROR_SUCCESS : GetLastError();
    }
    (void)SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW(path) ? ERROR_SUCCESS : GetLastError();
}

static void emit_selector_attempt(const WCHAR *root, const char *object_name, BOOL directory,
                                  const Selector *selector, const char *operation,
                                  const Variant *variant, DWORD sdk_access,
                                  unsigned long attempt_id) {
    WCHAR path[MAP_PATH_CAPACITY];
    HANDLE handle = NULL;
    DWORD fixture_code;
    DWORD open_code = ERROR_SUCCESS;
    DWORD source_code = ERROR_SUCCESS;
    DWORD api_code = ERROR_SUCCESS;
    DWORD cleanup_code = ERROR_SUCCESS;
    DWORD nt_status = ERROR_CALL_NOT_IMPLEMENTED;
    DWORD granted_access = 0;
    BOOL open_attempted = FALSE;
    BOOL source_attempted = FALSE;
    BOOL api_attempted = FALSE;
    BOOL cleanup_attempted = FALSE;

    ZeroMemory(path, sizeof(path));
    fixture_code = create_attempt_fixture(root, directory, attempt_id, path);
    if (fixture_code == ERROR_SUCCESS) {
        open_attempted = TRUE;
        open_code = open_fixture(path, directory, variant->access, &handle);
        if (open_code == ERROR_SUCCESS) {
            query_granted_access(handle, &nt_status, &granted_access);
            if (strcmp(operation, "query") == 0) {
                PSECURITY_DESCRIPTOR descriptor = NULL;
                api_attempted = TRUE;
                api_code = GetSecurityInfo(handle, SE_FILE_OBJECT, selector->information,
                                           NULL, NULL, NULL, NULL, &descriptor);
                if (descriptor != NULL) LocalFree(descriptor);
            } else {
                PSID owner = NULL;
                PSID group = NULL;
                PACL dacl = NULL;
                PACL sacl = NULL;
                PSECURITY_DESCRIPTOR descriptor = NULL;
                source_attempted = TRUE;
                source_code = source_descriptor(path, selector->information,
                                                &owner, &group, &dacl, &sacl, &descriptor);
                if (source_code == ERROR_SUCCESS) {
                    api_attempted = TRUE;
                    api_code = SetSecurityInfo(handle, SE_FILE_OBJECT, selector->information,
                                               owner, group, dacl, sacl);
                }
                if (descriptor != NULL) LocalFree(descriptor);
            }
            CloseHandle(handle);
        }
        cleanup_attempted = TRUE;
        cleanup_code = cleanup_attempt_fixture(path, directory);
    }

    fputs("{\"kind\":\"selector\",\"attempt_id\":", output_file);
    fprintf(output_file, "%lu,\"object\":", attempt_id);
    json_bytes(output_file, object_name);
    fputs(",\"operation\":", output_file);
    json_bytes(output_file, operation);
    fputs(",\"selector\":", output_file);
    json_bytes(output_file, selector->name);
    fprintf(output_file, ",\"information\":%lu,\"variant\":",
            (unsigned long)selector->information);
    json_bytes(output_file, variant->name);
    fprintf(output_file, ",\"sdk_access\":%lu,\"access\":%lu,\"fixture_code\":%lu,",
            (unsigned long)sdk_access, (unsigned long)variant->access,
            (unsigned long)fixture_code);
    if (open_attempted) fprintf(output_file, "\"open_code\":%lu,", (unsigned long)open_code);
    else fputs("\"open_code\":null,", output_file);
    if (source_attempted) fprintf(output_file, "\"source_code\":%lu,", (unsigned long)source_code);
    else fputs("\"source_code\":null,", output_file);
    if (api_attempted) fprintf(output_file, "\"api_code\":%lu,", (unsigned long)api_code);
    else fputs("\"api_code\":null,", output_file);
    if (cleanup_attempted) fprintf(output_file, "\"cleanup_code\":%lu,", (unsigned long)cleanup_code);
    else fputs("\"cleanup_code\":null,", output_file);
    if (open_attempted && open_code == ERROR_SUCCESS && nt_status == ERROR_SUCCESS) {
        fprintf(output_file, "\"ntstatus\":0,\"granted_access\":%lu}\n", (unsigned long)granted_access);
    } else if (open_attempted && open_code == ERROR_SUCCESS && nt_status != ERROR_CALL_NOT_IMPLEMENTED) {
        fprintf(output_file, "\"ntstatus\":%ld,\"granted_access\":null}\n", (long)(LONG)nt_status);
    } else {
        fputs("\"ntstatus\":null,\"granted_access\":null}\n", output_file);
    }
}

static size_t add_variant(Variant *variants, size_t count, const char *name, DWORD access) {
    size_t index;
    for (index = 0; index < count; ++index) {
        if (variants[index].access == access) return count;
    }
    variants[count].name = name;
    variants[count].access = access;
    return count + 1U;
}

static void map_selector(const WCHAR *root, const char *object_name, BOOL directory,
                         const Selector *selector, BOOL query,
                         unsigned long *attempt_counter) {
    DWORD sdk_access = 0;
    Variant variants[4];
    size_t count = 0;
    size_t index;
    const char *operation = query ? "query" : "set";

    if (query) QuerySecurityAccessMask(selector->information, &sdk_access);
    else SetSecurityAccessMask(selector->information, &sdk_access);

    count = add_variant(variants, count, "zero", 0U);
    count = add_variant(variants, count, "sdk", sdk_access);
    count = add_variant(variants, count, "plus_read_control", sdk_access | READ_CONTROL);
    if ((sdk_access & READ_CONTROL) != 0U) {
        count = add_variant(variants, count, "minus_read_control", sdk_access & ~READ_CONTROL);
    }
    for (index = 0; index < count; ++index) {
        *attempt_counter += 1UL;
        emit_selector_attempt(root, object_name, directory, selector, operation,
                              &variants[index], sdk_access, *attempt_counter);
    }
}

static BOOL create_fixture_root(const WCHAR *scratch_root, WCHAR *root) {
    WCHAR name[64];
    if (swprintf_s(name, ARRAY_COUNT(name), L"acl-native-map-%lu", (unsigned long)GetCurrentProcessId()) <= 0) {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    if (!join_path(root, MAP_PATH_CAPACITY, scratch_root, name)) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }
    return CreateDirectoryW(root, NULL);
}

static void cleanup_fixture_root(const WCHAR *root) {
    (void)RemoveDirectoryW(root);
}

int wmain(int argc, WCHAR **argv) {
    static const Selector selectors[] = {
        {"owner", OWNER_SECURITY_INFORMATION},
        {"group", GROUP_SECURITY_INFORMATION},
        {"dacl", DACL_SECURITY_INFORMATION},
        {"sacl", SACL_SECURITY_INFORMATION},
        {"label", LABEL_SECURITY_INFORMATION},
        {"attribute", ATTRIBUTE_SECURITY_INFORMATION},
        {"scope", SCOPE_SECURITY_INFORMATION},
        {"process_trust_label", PROCESS_TRUST_LABEL_SECURITY_INFORMATION},
        {"access_filter", ACCESS_FILTER_SECURITY_INFORMATION},
        {"basic", OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION},
        {"audit_label", SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION},
        {"all_defined", OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                        DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |
                        LABEL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION |
                        SCOPE_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION |
                        ACCESS_FILTER_SECURITY_INFORMATION},
        {"backup", BACKUP_SECURITY_INFORMATION}
    };
    static const WCHAR *privilege_names[] = {
        SE_SECURITY_NAME, SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME
    };
    WCHAR root[MAP_PATH_CAPACITY];
    HANDLE token = NULL;
    BOOL privileged = FALSE;
    errno_t open_error;
    size_t index;
    unsigned long attempt_counter = 0UL;

    if (argc != 4) {
        fwprintf(stderr, L"usage: %ls <scratch-root> <output-jsonl> <privileged:0|1>\n", argv[0]);
        return 2;
    }
    privileged = wcscmp(argv[3], L"1") == 0;
    open_error = _wfopen_s(&output_file, argv[2], L"wb");
    if (open_error != 0 || output_file == NULL) {
        fwprintf(stderr, L"could not open output: %ls\n", argv[2]);
        return 3;
    }
    (void)setvbuf(output_file, NULL, _IONBF, 0);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | (privileged ? TOKEN_ADJUST_PRIVILEGES : 0U), &token)) {
        emit_fatal("OpenProcessToken", GetLastError());
        fclose(output_file);
        return 4;
    }

    emit_environment(argv[1]);
    if (privileged) {
        for (index = 0; index < ARRAY_COUNT(privilege_names); ++index) {
            emit_privilege_enable(token, privilege_names[index]);
        }
    }
    emit_token(token);

    ZeroMemory(root, sizeof(root));
    if (!create_fixture_root(argv[1], root)) {
        DWORD code = GetLastError();
        emit_fatal("create_fixture_root", code);
        CloseHandle(token);
        fclose(output_file);
        cleanup_fixture_root(root);
        return 5;
    }

    for (index = 0; index < ARRAY_COUNT(selectors); ++index) {
        map_selector(root, "file", FALSE, &selectors[index], TRUE, &attempt_counter);
        map_selector(root, "file", FALSE, &selectors[index], FALSE, &attempt_counter);
        map_selector(root, "directory", TRUE, &selectors[index], TRUE, &attempt_counter);
        map_selector(root, "directory", TRUE, &selectors[index], FALSE, &attempt_counter);
    }

    cleanup_fixture_root(root);
    CloseHandle(token);
    fflush(output_file);
    fclose(output_file);
    output_file = NULL;
    return 0;
}
