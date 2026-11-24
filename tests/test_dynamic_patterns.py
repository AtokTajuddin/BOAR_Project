import tempfile
import unittest
from pathlib import Path

from BOAR_beta import (
    active_protections,
    check_binary_protections,
    detect_system_aslr,
    find_offset,
    generate_pattern,
)


class PatternTests(unittest.TestCase):
    def test_four_byte_windows_are_unique(self):
        pattern = generate_pattern(2000)
        windows = [pattern[index:index + 4] for index in range(len(pattern) - 3)]
        self.assertEqual(len(windows), len(set(windows)))

    def test_32_bit_offset_round_trip(self):
        pattern = generate_pattern(2000)
        needle = pattern[137:141]
        value = int.from_bytes(needle, "little")
        offset, bits, endian = find_offset(hex(value), pattern)
        self.assertEqual((offset, bits, endian), (137, 32, "little-endian"))

    def test_64_bit_offset_round_trip(self):
        pattern = generate_pattern(2000)
        needle = pattern[500:508]
        value = int.from_bytes(needle, "little")
        offset, bits, endian = find_offset(hex(value), pattern)
        self.assertEqual((offset, bits, endian), (500, 64, "little-endian"))

    def test_empty_pattern(self):
        self.assertEqual(generate_pattern(0), b"")


class HardeningDetectionTests(unittest.TestCase):
    def test_detect_system_aslr_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_file = Path(tmp) / "randomize_va_space"
            for raw, expected in (("0\n", "disabled"), ("1\n", "conservative"), ("2\n", "full")):
                proc_file.write_text(raw, encoding="utf-8")
                self.assertEqual(detect_system_aslr(proc_file), expected)
            self.assertIsNone(detect_system_aslr(Path(tmp) / "missing"))

    def test_active_protections_ignores_disabled_and_none(self):
        sample = {
            "canary": True,
            "nx": True,
            "pie": False,
            "relro": "none",
            "fortify": False,
            "aslr": "disabled",
        }
        self.assertEqual(active_protections(sample), ["canary", "nx"])
        sample["aslr"] = "full"
        sample["fortify"] = True
        self.assertEqual(active_protections(sample), ["canary", "nx", "fortify", "aslr"])

    def test_check_protections_on_system_binary_populates_expected_fields(self):
        if Path("/bin/ls").is_file():
            prots = check_binary_protections("/bin/ls")
            for key in ("canary", "nx", "pie", "relro", "fortify", "aslr"):
                self.assertIn(key, prots)


if __name__ == "__main__":
    unittest.main()
