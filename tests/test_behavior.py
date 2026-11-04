import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

from lab import catalog


class BehaviorCatalogTests(unittest.TestCase):
    def test_map_profile_uses_smoke_qualification_cases(self):
        smoke_darwin = [c["id"] for c in catalog.cases("darwin", "smoke")]
        map_darwin = [c["id"] for c in catalog.cases("darwin", "map")]
        smoke_windows = [c["id"] for c in catalog.cases("windows", "smoke")]
        map_windows = [c["id"] for c in catalog.cases("windows", "map")]
        self.assertEqual(map_darwin, smoke_darwin)
        self.assertEqual(map_windows, smoke_windows)

    def test_domain_catalogs_are_deterministic_and_large(self):
        from lab.behavior_catalog import manifest

        for platform, minimum in (("darwin", 1000), ("windows", 3000)):
            first = manifest(platform, "map")
            second = manifest(platform, "map")
            self.assertEqual(first, second)
            keys = [key for values in first.values() for key in values]
            self.assertEqual(len(keys), len(set(keys)))
            self.assertGreaterEqual(len(keys), minimum)
            self.assertTrue(all(values == sorted(values) for values in first.values()))

    def test_smoke_full_and_map_depths_are_monotonic(self):
        from lab.behavior_catalog import manifest

        for platform in ("darwin", "windows"):
            smoke = manifest(platform, "smoke")
            full = manifest(platform, "full")
            mapping = manifest(platform, "map")
            self.assertEqual(smoke.keys(), full.keys())
            self.assertEqual(full.keys(), mapping.keys())
            for domain in smoke:
                self.assertLessEqual(set(smoke[domain]), set(full[domain]))
                self.assertLessEqual(set(full[domain]), set(mapping[domain]))


class BehaviorEvidenceTests(unittest.TestCase):
    def test_validator_rejects_missing_duplicate_and_wrong_identity(self):
        from lab.behavior import RowWriter, validate_jsonl

        expected = ["api:one", "api:two"]
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "rows.jsonl"
            writer = RowWriter(path, "darwin", "api", expected)
            writer.emit("api:one", "ok", {"value": 1})
            writer.emit("api:two", "observe", {"value": 2})
            writer.finish()
            summary = validate_jsonl(path, "darwin", "api", expected)
            self.assertEqual(summary["completed"], 2)

            rows = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join(rows[:-2] + [rows[0], rows[-1]]) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_jsonl(path, "darwin", "api", expected)

            writer = RowWriter(path, "darwin", "api", expected)
            writer.emit("api:one", "ok", {})
            writer.finish()
            with self.assertRaises(ValueError):
                validate_jsonl(path, "darwin", "api", expected)

            writer = RowWriter(path, "windows", "api", expected)
            writer.emit("api:one", "ok", {})
            writer.emit("api:two", "ok", {})
            writer.finish()
            with self.assertRaises(ValueError):
                validate_jsonl(path, "darwin", "api", expected)

    def test_rows_are_append_only_and_partial_output_is_parseable(self):
        from lab.behavior import RowWriter, load_jsonl

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "rows.jsonl"
            writer = RowWriter(path, "windows", "lifecycle", ["lifecycle:a", "lifecycle:b"])
            writer.emit("lifecycle:a", "error", {"operation": "CreateFileW", "code": 5})
            rows = load_jsonl(path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["key"], "lifecycle:a")
            self.assertEqual(rows[0]["details"]["code"], 5)

    def test_summary_is_error_when_any_case_has_harness_error(self):
        from lab.behavior import RowWriter, validate_jsonl

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "rows.jsonl"
            writer = RowWriter(path, "darwin", "api", ["api:one"])
            writer.emit("api:one", "error", {"exception": "boom"})
            summary = writer.finish()
            self.assertEqual(summary["status"], "error")
            details = validate_jsonl(path, "darwin", "api", ["api:one"])
            self.assertEqual(details["counts"]["error"], 1)


class BehaviorRunnerTests(unittest.TestCase):
    def test_profile_depth_mapping(self):
        from ci.behavior import depth_for_profile

        self.assertEqual(depth_for_profile("smoke"), "smoke")
        self.assertEqual(depth_for_profile("full"), "full")
        self.assertEqual(depth_for_profile("map"), "map")
        self.assertEqual(depth_for_profile("stress"), "smoke")
        with self.assertRaises(ValueError):
            depth_for_profile("unknown")

    def test_workflow_exposes_map_profile(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows" / "native-acl.yml").read_text(encoding="utf-8")
        self.assertIn("options: [smoke, full, map, stress]", workflow)


class DarwinBehaviorPlanningTests(unittest.TestCase):
    def test_right_masks_cover_known_zero_all_and_unknown_bits(self):
        from lab.darwin_behavior import right_mask
        from lab.behavior_catalog import DARWIN_RIGHTS
        self.assertEqual(right_mask("read-data"), DARWIN_RIGHTS["read-data"])
        self.assertEqual(right_mask("zero"), 0)
        self.assertEqual(right_mask("all-known"), sum(DARWIN_RIGHTS.values()))
        self.assertEqual(right_mask("bit-31"), 1 << 31)
        with self.assertRaises(ValueError):
            right_mask("bit-32")

    def test_mode_policy_entries_preserve_order_and_principal(self):
        from lab.darwin_behavior import policy_entries
        user = "00112233-4455-6677-8899-aabbccddeeff"
        everyone = "abcdefab-cdef-abcd-efab-cdef0000000c"
        allow_deny = policy_entries("allow-deny", user, everyone, 0x80)
        deny_allow = policy_entries("deny-allow", user, everyone, 0x80)
        self.assertEqual([item["raw_flags"] & 0xF for item in allow_deny], [1, 2])
        self.assertEqual([item["raw_flags"] & 0xF for item in deny_allow], [2, 1])
        self.assertTrue(all(item["principal"] == user for item in allow_deny + deny_allow))
        self.assertEqual(policy_entries("none", user, everyone, 1), None)
        self.assertEqual(policy_entries("empty", user, everyone, 1), [])

    def test_every_mode_operation_has_a_native_right_mapping(self):
        from lab.behavior_catalog import manifest
        from lab.darwin_behavior import mode_access_dimensions, operation_right
        keys = manifest("darwin", "map")["mode-access"]
        for key in keys:
            obj, mode, policy, operation = mode_access_dimensions(key)
            self.assertIn(obj, ("file", "directory"))
            self.assertIsInstance(mode, int)
            self.assertTrue(policy)
            self.assertIsInstance(operation_right(obj, operation), int)

    def test_inheritance_keys_decode_all_dimensions(self):
        from lab.darwin_behavior import inheritance_dimensions
        self.assertEqual(inheritance_dimensions("inheritance:copy:deny:1f0"), ("copy", "deny", 0x1F0))

    def test_case_fixtures_are_created_only_under_owned_workspace(self):
        from lab.behavior import RowWriter
        from lab.darwin_behavior import _emit_case

        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            output = base / "evidence" / "rows.jsonl"
            workspace = base / "scratch" / "owned"
            writer = RowWriter(output, "darwin", "api", ["api:one"])
            observed = {}

            def case(root):
                observed["root"] = pathlib.Path(root).resolve()
                return {"ok": True}

            _emit_case(writer, object(), workspace, "api:one", case)
            writer.finish()
            self.assertEqual(observed["root"].parent, workspace.resolve())
            self.assertFalse(observed["root"].exists())

    def test_libc_fd_behavior_uses_bounded_oracle_helper(self):
        from lab.darwin_behavior import _api

        class Oracle:
            def __init__(self):
                self.fd_seen = None

            def write(self, path, data, follow=True, fd=None):
                self.fd_seen = fd

            def libc_read_fd(self, fd):
                self.fd_seen = fd
                return {"ok": True, "hex": "abcd"}

        with tempfile.TemporaryDirectory() as temporary:
            oracle = Oracle()
            result = _api(oracle, "api:libc:fd:one", pathlib.Path(temporary))
            self.assertEqual(result, {"ok": True, "hex": "abcd"})
            self.assertIsInstance(oracle.fd_seen, int)

    def test_darwin_explore_runs_the_selected_behavior_depth(self):
        from ci import explore as explore_module

        class FakeDarwin:
            def principal(self):
                return "00112233-4455-6677-8899-aabbccddeeff"

            def build_using_entry_api(self, principal):
                return b"fixture"

            def write(self, path, data, follow=True, fd=None):
                return None

            def read(self, path, follow=True, fd=None):
                return {"presence": "Present"}

            def libc_read(self, path, follow=True):
                return {"ok": True}

        fake_module = types.SimpleNamespace(Darwin=FakeDarwin)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            work = root / "work"
            out = root / "out"
            (work / "scratch").mkdir(parents=True)
            out.mkdir()
            with mock.patch.dict(sys.modules, {"lab.darwin": fake_module}), \
                    mock.patch.dict(os.environ, {"ACL_PROFILE": "map"}), \
                    mock.patch.object(explore_module.behavior, "run_all") as run_all:
                self.assertEqual(explore_module.explore("macos-arm64", work, out), 0)
            run_all.assert_called_once_with("darwin", "map", work, out,
                                            privileged=False, timeout=3600)


class WindowsBehaviorPlanningTests(unittest.TestCase):
    def test_every_windows_catalog_key_decodes(self):
        from lab.behavior_catalog import manifest
        from lab.windows_behavior import (
            access_dimensions,
            descriptor_dimensions,
            inheritance_dimensions as windows_inheritance_dimensions,
            selector_dimensions,
        )

        mapping = manifest("windows", "map")
        for key in mapping["descriptor-storage"]:
            self.assertIsInstance(descriptor_dimensions(key), tuple)
        for key in mapping["selector-combinations"]:
            obj, operation, selector = selector_dimensions(key)
            self.assertIn(obj, ("file", "directory"))
            self.assertIn(operation, ("query", "set"))
            self.assertIsInstance(selector, int)
        for key in mapping["access-evaluation"]:
            obj, policy, right = access_dimensions(key)
            self.assertIn(obj, ("file", "directory"))
            self.assertTrue(policy)
            self.assertTrue(right)
        for key in mapping["inheritance-events"]:
            event, kind, flags, child, protection = windows_inheritance_dimensions(key)
            self.assertTrue(event)
            self.assertIn(kind, ("allow", "deny"))
            self.assertGreaterEqual(flags, 0)
            self.assertIn(child, ("both", "file", "directory"))
            self.assertIn(protection, ("inherit", "protected"))

    def test_descriptor_state_catalog_covers_auto_inheritance_control_bits(self):
        from lab.behavior_catalog import manifest

        keys = set(manifest("windows", "map")["descriptor-storage"])
        states = {
            "dacl-auto-inherit-req", "sacl-auto-inherit-req",
            "dacl-auto-inherited", "sacl-auto-inherited",
            "both-auto-inherit-req", "both-auto-inherited",
            "rm-control-valid",
        }
        for obj in ("file", "directory"):
            for state in states:
                self.assertIn(f"descriptor-storage:state:{obj}:{state}", keys)

    def test_selector_catalog_maps_protection_and_unprotection_control_bits(self):
        from lab.behavior_catalog import manifest
        from lab.windows_behavior import selector_dimensions

        keys = set(manifest("windows", "map")["selector-combinations"])
        expected = {
            "selector-combinations:file:set:80000004",
            "selector-combinations:file:set:20000004",
            "selector-combinations:file:set:40000008",
            "selector-combinations:file:set:10000008",
            "selector-combinations:directory:set:a0000004",
            "selector-combinations:directory:set:50000008",
        }
        self.assertTrue(expected <= keys)
        for key in expected:
            obj, operation, selector = selector_dimensions(key)
            self.assertIn(obj, ("file", "directory"))
            self.assertEqual(operation, "set")
            self.assertGreater(selector, 0x0FFFFFFF)

    def test_right_masks_and_selector_access_variants_are_exact(self):
        from lab.windows_behavior import right_mask, selector_access_variants

        self.assertEqual(right_mask("read-data"), 1)
        self.assertEqual(right_mask("read-write"), 3)
        self.assertEqual(right_mask("generic-read-write"), 0xC0000000)
        self.assertEqual(right_mask("zero"), 0)
        variants = selector_access_variants(0x00020008)
        self.assertEqual(variants["zero"], 0)
        self.assertEqual(variants["sdk"], 0x00020008)
        self.assertEqual(variants["minus-read-control"], 8)
        self.assertEqual(len(variants.values()), len(set(variants.values())))

    def test_every_ace_type_has_a_byte_preserving_representative(self):
        from lab import wire
        from lab.windows_behavior import representative_ace

        sid = "S-1-5-21-1-2-3-4"
        for ace_type in tuple(range(22)) + (254,):
            raw = representative_ace(ace_type, 0x13, sid)
            parsed = wire.parse_acl(wire.acl([raw], revision=4))
            self.assertEqual(parsed["entries"][0]["type"], ace_type)
            self.assertEqual(parsed["entries"][0]["flags"], 0x13)
            self.assertEqual(parsed["entries"][0]["hex"], raw.hex())

    def test_access_policy_preserves_requested_ace_order(self):
        from lab import wire
        from lab.windows_behavior import policy_entries

        sid = "S-1-5-21-1-2-3-4"
        self.assertIsNone(policy_entries("null", sid, 1))
        self.assertEqual(policy_entries("empty", sid, 1), [])
        allow_deny = policy_entries("allow-deny", sid, 1)
        deny_allow = policy_entries("deny-allow", sid, 1)
        self.assertEqual([wire.parse_acl(wire.acl([entry]))["entries"][0]["type"]
                          for entry in allow_deny], [0, 1])
        self.assertEqual([wire.parse_acl(wire.acl([entry]))["entries"][0]["type"]
                          for entry in deny_allow], [1, 0])

    def test_windows_case_fixtures_stay_under_owned_workspace(self):
        from lab.behavior import RowWriter
        from lab.windows_behavior import _emit_case

        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            output = base / "evidence" / "rows.jsonl"
            workspace = base / "scratch" / "owned"
            writer = RowWriter(output, "windows", "descriptor-storage", ["case:one"])
            observed = {}

            def case(root):
                observed["root"] = pathlib.Path(root).resolve()
                return {"ok": True}

            _emit_case(writer, object(), workspace, "case:one", case)
            writer.finish()
            self.assertEqual(observed["root"].parent, workspace.resolve())
            self.assertFalse(observed["root"].exists())

    def test_windows_oracle_exposes_exact_sdk_access_masks(self):
        from lab.windows import Windows

        class Advapi:
            @staticmethod
            def QuerySecurityAccessMask(information, output):
                output._obj.value = information | 0x1000

            @staticmethod
            def SetSecurityAccessMask(information, output):
                output._obj.value = information | 0x2000

        oracle = object.__new__(Windows)
        oracle.a = Advapi()
        self.assertEqual(oracle.query_access_mask(8), 0x1008)
        self.assertEqual(oracle.set_access_mask(8), 0x2008)

    def test_windows_query_attempt_separates_open_and_api_failures(self):
        from lab.windows import Windows

        class Kernel:
            def __init__(self, handle):
                self.handle = handle
                self.closed = []

            def CreateFileW(self, *args):
                return self.handle

            def CloseHandle(self, handle):
                self.closed.append(handle)
                return 1

            def LocalFree(self, pointer):
                return None

        class Advapi:
            @staticmethod
            def GetSecurityInfo(handle, object_type, information, owner, group, dacl, sacl, output):
                return 5

        oracle = object.__new__(Windows)
        oracle.k = Kernel(123)
        oracle.a = Advapi()
        result = oracle.query_attempt("fixture", 7, 0x20000)
        self.assertEqual(result["open"], {"ok": True, "desired": 0x20000})
        self.assertEqual(result["api"]["code"], 5)
        self.assertEqual(oracle.k.closed, [123])

        oracle.k = Kernel(-1 & ((1 << (8 * __import__("ctypes").sizeof(__import__("ctypes").c_void_p))) - 1))
        with mock.patch("lab.windows.C.get_last_error", return_value=32, create=True):
            result = oracle.query_attempt("fixture", 7, 0x20000)
        self.assertEqual(result["open"]["code"], 32)
        self.assertIsNone(result["api"])

    def test_windows_set_attempt_separates_open_and_setter_failures(self):
        from lab import wire
        from lab.windows import Windows

        class Kernel:
            def __init__(self):
                self.closed = []

            @staticmethod
            def CreateFileW(*args):
                return 321

            def CloseHandle(self, handle):
                self.closed.append(handle)
                return 1

        class Advapi:
            @staticmethod
            def IsValidSecurityDescriptor(buffer):
                return 1

            @staticmethod
            def GetSecurityDescriptorDacl(buffer, present, dacl, defaulted):
                present._obj.value = 1
                dacl._obj.value = 0
                defaulted._obj.value = 0
                return 1

            @staticmethod
            def SetSecurityInfo(handle, object_type, information, owner, group, dacl, sacl):
                return 87

        oracle = object.__new__(Windows)
        oracle.k = Kernel()
        oracle.a = Advapi()
        data = wire.descriptor(dacl=None)
        result = oracle.set_attempt("fixture", data, 4, 0x40000)
        self.assertEqual(result["open"], {"ok": True, "desired": 0x40000})
        self.assertEqual(result["api"], {"ok": False, "code": 87})
        self.assertEqual(oracle.k.closed, [321])


if __name__ == "__main__":
    unittest.main()


class WindowsBehaviorExtendedPlanningTests(unittest.TestCase):
    def test_every_extended_windows_catalog_key_decodes(self):
        from lab.behavior_catalog import manifest
        from lab.windows_behavior import (
            authz_dimensions,
            lifecycle_dimensions,
            multiuser_dimensions,
            token_privilege_dimensions,
        )

        mapping = manifest("windows", "map")
        for key in mapping["lifecycle"]:
            self.assertTrue(lifecycle_dimensions(key))
        for key in mapping["token-privilege"]:
            dimensions = token_privilege_dimensions(key)
            self.assertIn(dimensions[0], ("token", "case", "privilege", "integrity"))
        for key in mapping["authz"]:
            self.assertTrue(authz_dimensions(key))
        for key in mapping["multiuser-map"]:
            role, scenario, right = multiuser_dimensions(key)
            self.assertIn(role, ("alice", "bob", "carol"))
            self.assertTrue(scenario)
            self.assertTrue(right)

    def test_authz_plans_cover_conditional_three_valued_logic(self):
        from lab.windows_behavior import authz_case_plan

        allow_true = authz_case_plan("authz:allow-true")
        allow_false = authz_case_plan("authz:allow-false")
        allow_unknown = authz_case_plan("authz:allow-unknown")
        deny_unknown = authz_case_plan("authz:deny-unknown")
        unknown_and_false = authz_case_plan("authz:unknown-and-false")
        unknown_or_true = authz_case_plan("authz:unknown-or-true")

        self.assertEqual((allow_true["ace"], allow_true["truth"], allow_true["expected"]),
                         ("allow", "true", "allow"))
        self.assertEqual((allow_false["ace"], allow_false["truth"], allow_false["expected"]),
                         ("allow", "false", "ignore"))
        self.assertEqual((allow_unknown["ace"], allow_unknown["truth"], allow_unknown["expected"]),
                         ("allow", "unknown", "ignore"))
        self.assertEqual((deny_unknown["ace"], deny_unknown["truth"], deny_unknown["expected"]),
                         ("deny", "unknown", "deny"))
        self.assertEqual(unknown_and_false["truth"], "false")
        self.assertEqual(unknown_or_true["truth"], "true")
        for plan in (allow_true, allow_false, allow_unknown, deny_unknown,
                     unknown_and_false, unknown_or_true):
            self.assertTrue(plan["sddl"].startswith("D:"))
            self.assertIn(plan["ace"], ("allow", "deny"))

    def test_selector_and_token_snapshots_have_stable_structural_plans(self):
        from lab.windows_behavior import token_information_plan

        plan = token_information_plan()
        self.assertEqual(plan["user"], (1, "sid-and-attributes"))
        self.assertEqual(plan["groups"], (2, "groups"))
        self.assertEqual(plan["privileges"], (3, "privileges"))
        self.assertEqual(plan["restricted-sids"], (11, "groups"))
        self.assertEqual(plan["integrity"], (25, "sid-and-attributes"))
        self.assertEqual(plan["capabilities"], (30, "groups"))
        self.assertEqual(plan["appcontainer-sid"], (31, "pointer-box"))


    def test_windows_open_observation_records_flags_and_error_boundary(self):
        from lab.windows import Windows

        class Kernel:
            @staticmethod
            def CreateFileW(*args):
                return 123

            @staticmethod
            def CloseHandle(handle):
                return 1

        oracle = object.__new__(Windows)
        oracle.k = Kernel()
        result = oracle.try_open_detailed("fixture", 7, share=3, creation=3, flags=0x02000000)
        self.assertEqual(result["open"], {"ok": True, "handle": 123})
        self.assertEqual(result["desired"], 7)
        self.assertEqual(result["share"], 3)
        self.assertEqual(result["creation"], 3)
        self.assertEqual(result["flags"], 0x02000000)

    def test_windows_file_identity_decodes_stable_handle_information(self):
        from lab.windows import Windows

        class Kernel:
            @staticmethod
            def GetFileInformationByHandle(handle, output):
                value = output._obj
                value.volume_serial = 0x12345678
                value.file_index_high = 0x01020304
                value.file_index_low = 0x05060708
                value.link_count = 3
                value.file_size_high = 1
                value.file_size_low = 2
                value.attributes = 0x20
                return 1

        oracle = object.__new__(Windows)
        oracle.k = Kernel()
        result = oracle.file_identity_handle(77)
        self.assertEqual(result["volume_serial"], 0x12345678)
        self.assertEqual(result["file_id"], "0102030405060708")
        self.assertEqual(result["link_count"], 3)
        self.assertEqual(result["size"], (1 << 32) | 2)
        self.assertEqual(result["attributes"], 0x20)


    def test_access_check_can_use_an_explicit_token(self):
        from lab import wire
        from lab.windows import Windows

        class Advapi:
            @staticmethod
            def IsValidSecurityDescriptor(buffer):
                return 1

            @staticmethod
            def MapGenericMask(mask, mapping):
                return None

            @staticmethod
            def AccessCheck(sd, token, mask, mapping, privs, size, granted, status):
                self_token = int(token)
                granted._obj.value = 0x1234 if self_token == 55 else 0
                status._obj.value = 1 if self_token == 55 else 0
                size._obj.value = 0
                return 1

        oracle = object.__new__(Windows)
        oracle.a = Advapi()
        data = wire.descriptor(dacl=wire.acl([]))
        result = oracle.access_check_token(data, 1, 55)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["granted"], 0x1234)

    def test_multiuser_catalog_is_map_only(self):
        from lab.behavior_catalog import manifest

        self.assertEqual(manifest("windows", "smoke")["multiuser-map"], [])
        self.assertEqual(manifest("windows", "full")["multiuser-map"], [])
        keys = manifest("windows", "map")["multiuser-map"]
        self.assertGreaterEqual(len(keys), 100)
        self.assertEqual(len(keys), len(set(keys)))

    def test_behavior_runner_can_select_domains_without_changing_catalog(self):
        from ci import behavior as behavior_module

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            work = root / "work"
            out = root / "out"
            (work / "scratch").mkdir(parents=True)
            out.mkdir()
            fake_result = {"returncode": 0, "timed_out": False}
            fake_summary = {"expected": 0, "completed": 0, "missing": [],
                            "counts": {"error": 0, "observe": 0, "ok": 0, "skip": 0}}
            with mock.patch.object(behavior_module.core, "command", return_value=fake_result), \
                    mock.patch.object(behavior_module.behavior, "validate_jsonl", return_value=fake_summary) as validate:
                behavior_module.run_all("windows", "map", work, out,
                                        domains=("lifecycle",), timeout=1)
            self.assertEqual(validate.call_count, 1)
            self.assertEqual(validate.call_args.args[2], "lifecycle")
    def test_windows_capture_normalizes_binary_and_path_evidence(self):
        import json
        from lab.windows_behavior import _capture

        result = _capture(lambda: {
            "raw": b"\x00\xff",
            "path": pathlib.Path("fixture"),
            "nested": [bytearray(b"ab")],
        })
        encoded = json.dumps(result, sort_keys=True)
        self.assertIn('"hex": "00ff"', encoded)
        self.assertEqual(result["value"]["raw"]["length"], 2)
        self.assertEqual(result["value"]["path"], "fixture")

    def test_all_windows_behavior_domains_have_dispatchers(self):
        from lab.behavior_catalog import WINDOWS_DOMAINS
        from lab.windows_behavior import implemented_domains

        self.assertEqual(set(implemented_domains()), set(WINDOWS_DOMAINS))

    def test_map_profile_is_materially_more_exhaustive_than_full(self):
        from lab.behavior_catalog import manifest

        full = manifest("windows", "full")
        mapping = manifest("windows", "map")
        self.assertGreater(sum(map(len, mapping.values())), 20000)
        self.assertGreater(len(mapping["descriptor-storage"]),
                           10 * len(full["descriptor-storage"]))
        self.assertGreater(len(mapping["inheritance-events"]), 1000)
        self.assertGreater(len(mapping["authz"]), 200)
    def test_windows_explore_runs_all_non_account_domains(self):
        from ci import explore as explore_module
        from lab.windows_behavior import implemented_domains

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            work = root / "work"
            out = root / "out"
            (work / "scratch").mkdir(parents=True)
            out.mkdir()
            result = {"returncode": 0, "timed_out": False}
            with mock.patch.dict(os.environ, {"ACL_PROFILE": "map"}), \
                    mock.patch.object(explore_module.shutil, "which", return_value="cl.exe"), \
                    mock.patch.object(explore_module.windows_native_map, "compile_command", return_value=["cl.exe"]), \
                    mock.patch.object(explore_module.core, "command", return_value=result), \
                    mock.patch.object(explore_module, "verify_mapper"), \
                    mock.patch.object(explore_module.behavior, "run_all") as run_all:
                self.assertEqual(explore_module.explore("windows-elevated", work, out), 0)
            kwargs = run_all.call_args.kwargs
            self.assertEqual(set(kwargs["domains"]), set(implemented_domains()) - {"multiuser-map"})
            self.assertFalse(kwargs["local_accounts"])
            self.assertTrue(kwargs["privileged"])

    def test_windows_lab_explore_includes_real_account_domain(self):
        from ci import explore as explore_module
        from lab.windows_behavior import implemented_domains

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            work = root / "work"
            out = root / "out"
            (work / "scratch").mkdir(parents=True)
            out.mkdir()
            result = {"returncode": 0, "timed_out": False}
            with mock.patch.dict(os.environ, {"ACL_PROFILE": "map"}), \
                    mock.patch.object(explore_module.shutil, "which", return_value="cl.exe"), \
                    mock.patch.object(explore_module.windows_native_map, "compile_command", return_value=["cl.exe"]), \
                    mock.patch.object(explore_module.core, "command", return_value=result), \
                    mock.patch.object(explore_module, "verify_mapper"), \
                    mock.patch.object(explore_module.behavior, "run_all") as run_all:
                self.assertEqual(explore_module.explore("windows-lab", work, out), 0)
            kwargs = run_all.call_args.kwargs
            self.assertEqual(set(kwargs["domains"]), set(implemented_domains()))
            self.assertTrue(kwargs["local_accounts"])
            self.assertTrue(kwargs["privileged"])

class GeneratedFilesystemBehaviorPlanningTests(unittest.TestCase):
    def test_map_catalog_reserves_generated_filesystem_observations(self):
        from lab.behavior_catalog import manifest
        darwin = manifest('darwin', 'map')['lifecycle']
        windows = manifest('windows', 'map')['lifecycle']
        for key in (
            'lifecycle:filesystem-primary',
            'lifecycle:filesystem-apfs-case-sensitive',
            'lifecycle:filesystem-hfs-plus',
        ):
            self.assertIn(key, darwin)
        for key in (
            'lifecycle:filesystem-primary',
            'lifecycle:filesystem-loopback-smb',
            'lifecycle:filesystem-refs',
        ):
            self.assertIn(key, windows)
        self.assertNotIn('lifecycle:filesystem-apfs-case-sensitive', manifest('darwin', 'full')['lifecycle'])
        self.assertNotIn('lifecycle:filesystem-refs', manifest('windows', 'full')['lifecycle'])
