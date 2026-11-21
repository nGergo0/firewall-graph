from parser import iter_continued_lines, iter_sections

import pytest



@pytest.mark.parametrize(
    ("input", "expected"),
    [
        pytest.param(["a\n"],   ["a"],  id="trailing newlines stripped"),
        pytest.param(["\na"],   ["a"],  id="leading newlines stripped"),
        pytest.param(["a "],    ["a "], id="trailing spaces kept"),
        pytest.param([" a"],    ["a"],  id="leading spaces (indentation) stripped"),
        pytest.param(
            [" \na"],
            ["a"],
            id="leading whitespaces stripped"
        ),
        pytest.param(
            ["a \\\n", "  b\n"],
            ["a b"],
            id = "1 continuated line"
        ), 
        pytest.param(
            ["a \\\n", "  b\n", "c\n"],
            ["a b", "c"],
            id = "2 continuated line"
        ),
        pytest.param(
            ["protocol=\\\n", "  tcp \\\n", "  action=drop\n"],
            ["protocol=tcp action=drop"],
            id = "multiple continued lines"
        )
    ],
)
def test_iter_continued_lines(input, expected):
    result = list(iter_continued_lines(input)) 
    assert result == expected

@pytest.mark.parametrize(
    ("input", "expected"),
    [
        pytest.param(["/section"],   [],  id="only section"),
        pytest.param(["line"],   [],  id="only line"),
        pytest.param(["# comment"],  [], id="comments"),
        pytest.param(["/section", "# comment"], [],  id="commnets with section"),
        pytest.param(["/section1", "/section2"], [], id="only sections"),
        pytest.param(["/section", "line"], [("/section", "line")], id="1 line"),
        pytest.param(["/section", "line1", "line2"], [("/section", "line1"), ("/section", "line2")], id="2 lines"),
        pytest.param(["/section1", "line1", "/section2", "line2"], [("/section1", "line1"), ("/section2", "line2")], id="2 sections"),
    ],
)
def test_iter_sections(input, expected):
    result = list(iter_sections(input)) 
    assert result == expected


@pytest.mark.parametrize(
    ("input", "expected"),
    [
        ("/a/b",    "/a/b"),
        ("/a/b ",   "/a/b"),
        ("/a b",    "/a/b"),
        ("/a   b",  "/a/b"),
        ("/a /b",   "/a/b"),
        ("/a   /b", "/a/b"),
        ("/a/b/",   "/a/b"),
    ],
)
def test_section_parsing(input, expected):
    result = list(iter_sections([input, "line"]))
    assert result[0][0] == expected
