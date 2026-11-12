from security_dive.config import glob_match
from security_dive.units import extract_source

from .conftest import PARSER_C


def test_glob_match():
    assert glob_match("boot/**", "boot/a/b.c")
    assert glob_match("**/test/**", "boot/x/test/t.c")
    assert glob_match("**/test/**", "test/t.c")
    assert not glob_match("boot/*.c", "boot/a/b.c")
    assert glob_match("src/bootutil_misc.[ch]", "src/bootutil_misc.h")
    assert not glob_match("src/bootutil_misc.[ch]", "src/bootutil_misc.o")


def test_area_and_scope(cfg):
    p = cfg.project("demo")
    assert p.in_scope("src/parser.c")
    assert not p.in_scope("test/t.c")
    assert not p.in_scope("src/README.md")
    assert p.area_for("src/parser.h").name == "parsing"
    assert p.area_for("src/util.c").name == "misc"


def test_extract_functions_and_variants():
    units = extract_source("src/parser.c", PARSER_C.encode(), "parsing", 5)
    by_key = {u.key: u for u in units}
    assert list(by_key) == [
        "src/parser.c",
        "src/parser.c::check_len",
        "src/parser.c::parse",
        "src/parser.c::parse@2",
    ]
    assert by_key["src/parser.c::check_len"].start_line == 3
    assert by_key["src/parser.c::check_len"].end_line == 6
    assert by_key["src/parser.c::parse@2"].start_line == 11


def test_pointer_return_and_macro_type():
    src = b"static inline int *get(void) { return 0; }\nFIH_RET_TYPE val(void) { FIH_RET(x); }\n"
    names = [u.symbol for u in extract_source("a.h", src, "a", 1) if u.kind == "function"]
    assert names == ["get", "val"]


def test_hash_tracks_function_body_only():
    a = extract_source("f.c", b"int f(void) { return 1; }\nint g(void) { return 2; }\n", "a", 1)
    b = extract_source("f.c", b"int f(void) { return 1; }\nint g(void) { return 3; }\n", "a", 1)
    ha = {u.key: u.content_hash for u in a}
    hb = {u.key: u.content_hash for u in b}
    assert ha["f.c::f"] == hb["f.c::f"]
    assert ha["f.c::g"] != hb["f.c::g"]
    assert ha["f.c"] != hb["f.c"]


def _fns(src: str):
    return [(u.key.split("::")[1], u.start_line, u.end_line)
            for u in extract_source("x.c", src.encode(), "a", 1) if u.kind == "function"]


def test_if_inside_body_and_signature():
    src = """\
int
f(int a
#ifdef X
  , int b
#endif
  )
{
#ifdef Y
    if (a) {
#else
    if (!a) {
#endif
        return 1;
    }
    return 0;
}

int g(void)
{
    return 2;
}
"""
    assert _fns(src) == [("f", 1, 16), ("g", 18, 21)]


def test_signature_variants_merge():
    src = """\
#if X
static int h(int a, int b,
#else
static int h(int a,
#endif
             int c)
{
    return a;
}
"""
    assert _fns(src) == [("h", 2, 9)]


def test_nested_variants_all_found():
    # Mirrors bootutil_find_key.c: four variants over nested groups.
    src = """\
#ifndef BYPASS
#ifndef BUILTIN
#ifndef HW
int k(int a)
{
    return 1;
}
#else
int k(int a, int b)
{
    return 2;
}
#endif
#endif
#else
#ifndef HW
int k(void)
{
    return 3;
}
#else
int k(int b)
{
    return 4;
}
#endif
#endif
"""
    assert [s for _n, s, _e in _fns(src)] == [4, 9, 17, 22]


def test_multiline_comment_on_directive():
    src = """\
#if A
int a(void)
{
    return 0;
}
#endif /* A ||
          B */

int b(void)
{
    return 1;
}
"""
    assert _fns(src) == [("a", 2, 5), ("b", 9, 12)]


def test_packed_struct_is_not_a_function():
    src = "STRUCT_PACKED image_header {\n    int x;\n};\nint f(void) { return 0; }\n"
    assert _fns(src) == [("f", 4, 4)]
