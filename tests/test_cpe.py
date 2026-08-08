from models.technology import Technology
from collectors.sources.cpe import CPEResolver
from collectors.sources.nvd import NVDSource


technology = Technology(
    name="MySQL",
    version="8.0.36",
)

cpe_resolver = CPEResolver()

technology.cpe = cpe_resolver.resolve(
    technology.name,
    technology.version,
)

print(
    "Resolved CPE:",
    technology.cpe,
)

source = NVDSource()

vulnerabilities = source.search(
    technology,
)

print(
    "Total parsed vulnerabilities:",
    len(vulnerabilities),
)

for vulnerability in vulnerabilities[:5]:
    print()
    print(
        "CVE:",
        vulnerability.cve,
    )
    print(
        "CVSS:",
        vulnerability.cvss,
    )
    print(
        "CVSS version:",
        vulnerability.cvss_version,
    )
    print(
        "Description:",
        vulnerability.description,
    )