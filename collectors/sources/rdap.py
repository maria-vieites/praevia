"""
RDAP source.

Provides public registration and network information for IP addresses.
"""

import time

import requests

from utils.http import get_json


RDAP_API_URL = "https://rdap.org/ip"

RDAP_RETRY_DELAY = 2


class RDAPSource:
    """
    Provides access to public RDAP information for IP addresses.
    """

    def search(
        self,
        ip_address: str,
    ) -> dict | None:
        """
        Retrieves RDAP information for an IP address.

        If the RDAP service returns HTTP 429, the request is retried
        once after a short delay.

        Returns:
            The RDAP response as a dictionary, or None if unavailable.
        """

        url = f"{RDAP_API_URL}/{ip_address}"

        try:
            response = get_json(
                url,
            )

            if isinstance(
                response,
                dict,
            ):
                return response

            return None

        except requests.HTTPError as error:

            if (
                error.response is None
                or error.response.status_code != 429
            ):
                print(
                    f"RDAP unavailable for {ip_address}: "
                    f"{error}"
                )

                return None

            print(
                f"RDAP rate limit reached for "
                f"{ip_address}. Retrying..."
            )

            time.sleep(
                RDAP_RETRY_DELAY,
            )

            try:
                response = get_json(
                    url,
                )

            except requests.RequestException as retry_error:

                print(
                    f"RDAP unavailable for {ip_address}: "
                    f"{retry_error}"
                )

                return None

            if not isinstance(
                response,
                dict,
            ):
                return None

            return response

        except requests.RequestException as error:

            print(
                f"RDAP unavailable for {ip_address}: "
                f"{error}"
            )

            return None

    def extract_organization(
        self,
        data: dict,
    ) -> str | None:
        """
        Extracts an organization or entity name from RDAP data.
        """

        entities = data.get(
            "entities",
            [],
        )

        if not isinstance(
            entities,
            list,
        ):
            return None

        preferred_roles = (
            "registrant",
            "administrative",
            "technical",
        )

        for role in preferred_roles:

            for entity in entities:

                if not isinstance(
                    entity,
                    dict,
                ):
                    continue

                roles = entity.get(
                    "roles",
                    [],
                )

                if role not in roles:
                    continue

                value = self._extract_entity_name(
                    entity,
                )

                if value:
                    return value

        for entity in entities:

            if not isinstance(
                entity,
                dict,
            ):
                continue

            value = self._extract_entity_name(
                entity,
            )

            if value:
                return value

        return None

    def extract_network(
        self,
        data: dict,
    ) -> str | None:
        """
        Extracts the IP network/prefix reported by RDAP.
        """

        cidrs = data.get(
            "cidr0_cidrs",
        )

        if isinstance(
            cidrs,
            list,
        ):

            for cidr in cidrs:

                if not isinstance(
                    cidr,
                    dict,
                ):
                    continue

                prefix = cidr.get(
                    "v4prefix",
                )

                length = cidr.get(
                    "length",
                )

                if (
                    prefix is not None
                    and length is not None
                ):
                    return (
                        f"{prefix}/{length}"
                    )

                prefix = cidr.get(
                    "v6prefix",
                )

                if (
                    prefix is not None
                    and length is not None
                ):
                    return (
                        f"{prefix}/{length}"
                    )

        start = data.get(
            "startAddress",
        )

        end = data.get(
            "endAddress",
        )

        if start and end:
            return f"{start} - {end}"

        return None

    def _extract_entity_name(
        self,
        entity: dict,
    ) -> str | None:
        """
        Extracts a human-readable entity name from an RDAP vCard.
        """

        vcard_array = entity.get(
            "vcardArray",
        )

        if not isinstance(
            vcard_array,
            list,
        ):
            return None

        if len(vcard_array) < 2:
            return None

        properties = vcard_array[1]

        if not isinstance(
            properties,
            list,
        ):
            return None

        for property_data in properties:

            if not isinstance(
                property_data,
                list,
            ):
                continue

            if len(property_data) < 4:
                continue

            if property_data[0] != "org":
                continue

            value = property_data[3]

            if isinstance(
                value,
                str,
            ) and value.strip():

                return value.strip()

            if isinstance(
                value,
                list,
            ):

                value = ", ".join(
                    str(item)
                    for item in value
                ).strip()

                if value:
                    return value

        for property_data in properties:

            if not isinstance(
                property_data,
                list,
            ):
                continue

            if len(property_data) < 4:
                continue

            if property_data[0] != "fn":
                continue

            value = property_data[3]

            if isinstance(
                value,
                str,
            ) and value.strip():

                return value.strip()

        return None