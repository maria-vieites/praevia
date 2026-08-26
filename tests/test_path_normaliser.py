"""
Manual tests for path normalisation.
"""

from utils.path_normaliser import normalise_path


def main() -> None:
    tests = (
        (
            "/api/v2/downloads/release/ endpoint returns error/",
            "/api/v2/downloads/release/",
        ),
        (
            "/api/",
            "/api/",
        ),
        (
            "/robots.txt",
            "/robots.txt",
        ),
        (
            "/sitemap.xml",
            "/sitemap.xml",
        ),
        (
            "/users/12345/profile/",
            "/users/",
        ),
        (
            "/files/550e8400-e29b-41d4-a716-446655440000/",
            "/files/",
        ),
        (
            "/index.php",
            "/",
        ),
    )

    passed = 0

    print("=== Path normalisation manual tests ===")

    for path, expected in tests:

        result = normalise_path(
            path,
        )

        if result == expected:
            print(
                f"[PASS] {path}"
                f" -> {result}"
            )
            passed += 1
        else:
            print(
                f"[FAIL] {path}"
                f" -> {result}"
                f" (expected {expected})"
            )

    print()
    print(
        f"=== Result ===\n"
        f"{passed}/{len(tests)} tests passed."
    )


if __name__ == "__main__":
    main()