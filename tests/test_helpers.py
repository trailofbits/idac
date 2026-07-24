from tests.helpers import normalize_pseudocode_call_arguments


def test_normalize_pseudocode_call_arguments_handles_ida_version_formats() -> None:
    pseudocode = (
        "legacy = add(2, 3);\n"
        'value = add(a: 2, b: 3);\nprintf(format: "tiny:%d\\n", value);\n'
        'describe(text: "example(a: 2), escaped: \\"quote\\"");\n'
        "marker = '(label: value)';\n"
        "selected = choose(flag ? left : right, fallback: other);\n"
        "documented = call(argument: value /* example(label: value) */);\n"
        "result = call(value); // example(label: value)\n"
        "consume(std::move(value));"
    )

    assert normalize_pseudocode_call_arguments(pseudocode) == (
        'legacy = add(2, 3);\nvalue = add(2, 3);\nprintf("tiny:%d\\n", value);\n'
        'describe("example(a: 2), escaped: \\"quote\\"");\n'
        "marker = '(label: value)';\n"
        "selected = choose(flag ? left : right, other);\n"
        "documented = call(value /* example(label: value) */);\n"
        "result = call(value); // example(label: value)\n"
        "consume(std::move(value));"
    )
