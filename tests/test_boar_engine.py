import json
import shutil
import subprocess
import unittest
from pathlib import Path

from boar_engine import (
    analyze_source,
    build_sarif,
    load_rules,
    reaches_threshold,
    sort_findings,
)


RULES = load_rules()
ROOT = Path(__file__).resolve().parent.parent


def findings_for(source):
    return sort_findings(analyze_source(source, "sample.c", RULES))


def ids(source):
    return [finding["id"] for finding in findings_for(source)]


class StaticMatcherTests(unittest.TestCase):
    def test_gets_is_detected_but_comment_and_string_are_ignored(self):
        source = """\
void f(char *input) {
    char buffer[8];
    // gets(buffer);
    printf("gets(buffer)");
    gets(buffer);
}
"""
        findings = findings_for(source)
        gets = [finding for finding in findings if finding["id"] == "BOAR-MEM-001"]
        self.assertEqual(len(gets), 1)
        self.assertEqual(gets[0]["line"], 5)

    def test_scanf_validates_missing_width_and_excess_width_against_buffer(self):
        source = """\
void f(void) {
    char buffer[8];
    scanf("%s", buffer);
    scanf("%7s", buffer);
    scanf("%8s", buffer);
    scanf("%99s", buffer);
    scanf("%*s");
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-004"]
        # Line 3 (%s unbounded), line 5 (%8s writes 9 bytes into 8), line 6 (%99s writes 100 bytes into 8).
        # Line 4 (%7s fits in 8) and line 7 (%*s assignment-suppressed) are safe.
        self.assertEqual([f["line"] for f in findings], [3, 5, 6])

    def test_scanf_tracks_multiple_arguments_accurately(self):
        source = """\
void f(void) {
    int id;
    char small[4];
    char big[32];
    scanf("%d %3s %31[a-z]", &id, small, big);
    scanf("%d %4s", &id, small);
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-004"]
        self.assertEqual([f["line"] for f in findings], [6])

    def test_scoped_buffers_and_constants_do_not_clobber_across_functions(self):
        source = """\
#define SMALL_BUF 8
enum { LARGE_BUF = 64 };

void first(void) {
    char buffer[SMALL_BUF];
    strcpy(buffer, "123456789");
}

void second(void) {
    char buffer[LARGE_BUF];
    strcpy(buffer, "123456789");
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-002"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 6)
        self.assertEqual(findings[0]["confidence"], "high")

    def test_strcpy_literal_is_suppressed_when_it_fits(self):
        source = """\
void f(char *input) {
    char buffer[16];
    strcpy(buffer, "ok");
    strcpy(buffer, input);
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-002"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 4)

    def test_memcpy_sizeof_destination_ok_but_wrong_sizeof_or_excess_constant_flagged(self):
        source = """\
#define COPY_LEN 32
void f(char *input, int n) {
    char dst[16];
    char src[64];
    memcpy(dst, input, sizeof(dst));
    memcpy(dst, src, sizeof(src));
    memcpy(dst, input, COPY_LEN);
    memcpy(dst, input, n);
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-005"]
        self.assertEqual([f["line"] for f in findings], [6, 7, 8])
        self.assertEqual(findings[0]["confidence"], "high")
        self.assertEqual(findings[1]["confidence"], "high")

    def test_suppression_comment_is_honored(self):
        source = """\
void f(void) {
    char buffer[8];
    gets(buffer); // boar:ignore
}
"""
        self.assertEqual(ids(source), [])

    def test_malloc_sizeof_deref_is_not_flagged_as_alloc_arithmetic(self):
        source = """\
struct item { int a; };
void f(size_t n) {
    struct item *one = malloc(sizeof(*one));
    struct item *fixed = malloc(16 * sizeof(*fixed));
    struct item *dyn = malloc(n * sizeof(*dyn));
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-008"]
        self.assertEqual([f["line"] for f in findings], [5])


class NewRuleTests(unittest.TestCase):
    def test_bounded_string_copy_catches_strncat_sizeof_and_unterminated_strncpy(self):
        source = """\
void f(const char *src) {
    char buf[16] = "hi";
    strncat(buf, src, sizeof(buf));
    strncpy(buf, src, sizeof(buf));
}

void safe(const char *src) {
    char buf[16];
    strncpy(buf, src, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\\0';
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-011"]
        self.assertEqual([f["line"] for f in findings], [3, 4])
        self.assertEqual(findings[0]["confidence"], "high")
        self.assertEqual(findings[1]["confidence"], "medium")

    def test_input_read_length_catches_overflow_and_signed_read(self):
        source = """\
void f(int fd, int signed_len) {
    char buf[32];
    fgets(buf, sizeof(buf), stdin);
    fgets(buf, 128, stdin);
    read(fd, buf, signed_len);
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-012"]
        self.assertEqual([f["line"] for f in findings], [4, 5])
        self.assertEqual(findings[0]["confidence"], "high")
        self.assertEqual(findings[1]["confidence"], "medium")

    def test_sizeof_pointer_mismatch_detected_for_pointers_and_array_params(self):
        source = """\
struct node { int a; int b; int c; };

void wipe(char param_buf[64], char *ptr) {
    char local_buf[64];
    memset(local_buf, 0, sizeof(local_buf));
    memset(param_buf, 0, sizeof(param_buf));
    memset(ptr, 0, sizeof(ptr));
    struct node *n = malloc(sizeof(n));
    struct node *ok = malloc(sizeof(*ok));
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-013"]
        self.assertEqual([f["line"] for f in findings], [6, 7, 8])

    def test_return_stack_address_detected_but_static_and_heap_allowed(self):
        source = """\
char *bad_array(void) {
    char local[32];
    return local;
}

int *bad_scalar(void) {
    int value = 7;
    return &value;
}

char *ok_static(void) {
    static char persist[32];
    return persist;
}

char *ok_heap(void) {
    char *p = malloc(32);
    return p;
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-014"]
        self.assertEqual([f["line"] for f in findings], [3, 8])


class LifetimeTests(unittest.TestCase):
    def test_double_free_is_reported_once(self):
        source = """\
void f(void) {
    char *p = malloc(16);
    free(p);
    free(p);
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-009"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 4)

    def test_null_assignment_prevents_double_free_false_positive(self):
        source = """\
void f(void) {
    char *p = malloc(16);
    free(p);
    p = NULL;
    free(p);
}
"""
        self.assertNotIn("BOAR-MEM-009", ids(source))

    def test_early_return_after_free_prevents_uaf_false_positive(self):
        source = """\
struct item { int value; };
void f(struct item *p, int err) {
    if (err) {
        free(p);
        return;
    }
    p->value = 1;
}
"""
        self.assertNotIn("BOAR-MEM-010", ids(source))

    def test_conditional_free_without_return_catches_fallthrough_uaf(self):
        source = """\
struct item { int value; };
void f(struct item *p, int err) {
    if (err) {
        free(p);
    }
    p->value = 1;
}
"""
        findings = [finding for finding in findings_for(source)
                    if finding["id"] == "BOAR-MEM-010"]
        self.assertEqual([f["line"] for f in findings], [6])

    def test_freeing_different_pointers_is_not_a_double_free(self):
        source = """\
struct item { int value; };
void f(struct item *p, struct item *q) {
    free(p);
    free(q);
    p->value = 1;
}
"""
        result = ids(source)
        self.assertNotIn("BOAR-MEM-009", result)
        self.assertIn("BOAR-MEM-010", result)

    def test_reassignment_clears_the_freed_state(self):
        source = """\
struct item { int value; };
void f(struct item *p) {
    free(p);
    p = malloc(sizeof(*p));
    p->value = 1;
}
"""
        result = ids(source)
        self.assertNotIn("BOAR-MEM-009", result)
        self.assertNotIn("BOAR-MEM-010", result)


class RuleSetAndWebParityTests(unittest.TestCase):
    def test_default_rule_count_and_threshold(self):
        self.assertEqual(len(RULES), 14)
        findings = findings_for("void f(char *p) { gets(p); }")
        self.assertTrue(reaches_threshold(findings, "critical"))
        self.assertTrue(reaches_threshold(findings, "high"))
        self.assertTrue(reaches_threshold(findings, "low"))
        self.assertFalse(reaches_threshold([], "low"))

    def test_sarif_report_structure_and_mappings(self):
        source = "void f(char *p) { char buf[8]; gets(buf); scanf(\"%16s\", buf); }\n"
        findings = findings_for(source)
        sarif = build_sarif("src/app.c", findings, RULES)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "BOAR")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 14)
        self.assertEqual(len(run["results"]), 2)
        first = run["results"][0]
        self.assertEqual(first["ruleId"], "BOAR-MEM-001")
        self.assertEqual(first["level"], "error")
        loc = first["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "sample.c")
        self.assertEqual(loc["region"]["startLine"], 1)

    @unittest.skipUnless(shutil.which("node"), "node is required for web parity test")
    def test_web_engine_matches_python_engine(self):
        corpus = """\
#define LIMIT 16
struct item { int size; };

char *demo(char *input, int len, int flag) {
    char small[8];
    char med[LIMIT];
    gets(small);
    scanf("%12s", small);
    strncat(med, input, sizeof(med));
    fgets(small, 32, stdin);
    memset(input, 0, sizeof(input));
    struct item *p = malloc(sizeof(*p));
    if (flag) {
        free(p);
    }
    p->size = 2;
    return small;
}
"""
        py_findings = findings_for(corpus)
        script = (
            "globalThis.window = globalThis;"
            "require('./docs/rules.js');"
            "require('./docs/app.js');"
            "const src = JSON.parse(process.argv[1]);"
            "console.log(JSON.stringify(globalThis.BOAR_ANALYZE(src, 'sample.c')));"
        )
        proc = subprocess.run(
            ["node", "-e", script, json.dumps(corpus)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        js_findings = json.loads(proc.stdout)
        self.assertEqual(
            [(f["id"], f["line"], f["severity"], f["confidence"]) for f in py_findings],
            [(f["id"], f["line"], f["severity"], f["confidence"]) for f in js_findings],
        )


if __name__ == "__main__":
    unittest.main()
