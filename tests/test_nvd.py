import requests


url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

params = {
    "cpeMatchString": "cpe:2.3:a:*:MySQL:8.0.36",
    "resultsPerPage": 20,
}

response = requests.get(
    url,
    params=params,
    timeout=20,
)

response.raise_for_status()

data = response.json()

print(
    "Total results:",
    data.get("totalResults"),
)

for product in data.get(
    "products",
    [],
):

    cpe = product.get(
        "cpe",
        {},
    )

    print(
        "CPE:",
        cpe.get("cpeName"),
    )

    print(
        "Titles:",
        cpe.get("titles"),
    )

    print()