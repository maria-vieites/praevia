"""
Manual test for Wappalyzer.
"""

from wappalyzer import Wappalyzer


def main() -> None:

    with Wappalyzer() as scanner:

        result = scanner.analyze(
            #"https://python.org",
            "https://wordpress.org"
        )

    print(result)


if __name__ == "__main__":
    main()