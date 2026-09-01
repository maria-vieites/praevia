"""
Pentest-oriented investigation prioritisation.

Produces a deterministic 0-100 investigation-priority score.

The score represents investigation priority for a pentester.
It is not a probability of exploitation and it does not replace
the underlying evidence.
"""

from urllib.parse import urlparse

from models.correlation import CorrelationStrength
from models.finding import Finding
from models.investigation_priority import InvestigationPriority
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class PriorisationEngine:
    """
    Calculate investigation priorities.

    Priority bands:

        80-100 -> HIGH
        50-79  -> MEDIUM
        20-49  -> LOW
         0-19  -> INFO
    """

    HIGH_THRESHOLD = 80.0
    MEDIUM_THRESHOLD = 50.0
    LOW_THRESHOLD = 20.0

    def prioritise(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """Assign priority score, level and rationale to every finding."""

        for finding in data.findings:

            finding.priority_raw_score = None

            score, rationale = self._score(
                target,
                finding,
            )

            raw_score = (
                finding.priority_raw_score
                if finding.priority_raw_score is not None
                else score
            )

            score = max(
                0.0,
                min(
                    100.0,
                    score,
                ),
            )

            finding.priority_raw_score = round(
                raw_score,
                1,
            )

            finding.priority_score = round(
                score,
                1,
            )

            finding.priority_cap = None
            finding.priority_cap_reason = None

            cap_reason = next(
                (
                    reason
                    for reason in rationale
                    if "capped" in reason.lower()
                ),
                None,
            )

            if (
                cap_reason is not None
                and raw_score > score
            ):

                finding.priority_cap = finding.priority_score
                finding.priority_cap_reason = cap_reason

            # Classification follows the rounded value exposed by the
            # finding so the displayed score and priority can never
            # disagree at a threshold boundary.
            finding.priority = (
                self._priority_for_score(
                    finding.priority_score,
                )
            )

            finding.priority_rationale = rationale

    def _score(
        self,
        target: Target,
        finding: Finding,
    ) -> tuple[float, list[str]]:
        """Dispatch scoring according to finding category."""

        if finding.category == "vulnerability":

            return self._score_vulnerability(
                finding,
            )

        if finding.category == "internet_exposure":

            return self._score_exposure(
                finding,
            )

        if finding.category == "historical_surface":

            return self._score_historical(
                finding,
            )

        if finding.category == "repository":

            return self._score_repository(
                target,
                finding,
            )

        return self._score_generic(
            finding,
        )

    # ------------------------------------------------------------------
    # Vulnerability
    # ------------------------------------------------------------------

    def _score_vulnerability(
        self,
        finding: Finding,
    ) -> tuple[float, list[str]]:
        """
        Score a vulnerability finding.

        CVSS is the primary technical severity signal.
        Confidence determines how strongly the finding should be trusted.
        A public PoC is a material investigative signal because it can
        substantially reduce the effort needed to validate a finding.

        The score represents pentest investigation interest, not
        exploitability probability.
        """

        cvss = self._normalise_cvss(
            self._signal_number(
                finding,
                "cvss",
            ),
        )

        confidence = self._confidence(
            finding.confidence,
        )

        evidence_quality = self._evidence_quality(
            finding,
        )

        poc = self._has_signal(
            finding,
            "poc",
        )

        if cvss is None:

            cvss_points = 0.0

        else:

            cvss_points = (
                cvss / 10.0
            ) * 45.0

        confidence_points = (
            confidence * 20.0
        )

        evidence_points = (
            evidence_quality * 0.15
        )

        # PoC is deliberately worth 20 points. This is not a risk
        # multiplier: it represents practical actionability for the
        # pentester.
        poc_points = (
            20.0
            if poc
            else 0.0
        )

        score = (
            cvss_points
            + confidence_points
            + evidence_points
            + poc_points
        )

        rationale = [
            (
                f"CVSS "
                f"{cvss:.1f}/10: "
                f"+{cvss_points:.1f}/45."
            )
            if cvss is not None
            else (
                "No usable CVSS score was available: "
                "+0.0/45."
            ),
            (
                f"Finding confidence "
                f"{confidence:.2f}: "
                f"+{confidence_points:.1f}/20."
            ),
            (
                f"Independent evidence quality "
                f"{evidence_quality:.1f}/100: "
                f"+{evidence_points:.1f}/15."
            ),
            (
                "Public proof-of-concept available: "
                f"+{poc_points:.1f}/20."
                if poc
                else
                "No public proof-of-concept signal: "
                "+0.0/20."
            ),
        ]

        return score, rationale

    # ------------------------------------------------------------------
    # Internet exposure
    # ------------------------------------------------------------------

    def _score_exposure(
        self,
        finding: Finding,
    ) -> tuple[float, list[str]]:
        """
        Score publicly observable Internet exposure.

        Components:

            1. Hostname-to-IP relationship strength: 35 points.
            2. Observed service surface: 25 points.
            3. Service association confidence with the hostname: 20 points.
            4. Contextual exposure: 10 points.
            5. Port breadth: 10 points.

        InternetDB observations are about IP-level infrastructure.
        They are not automatically vulnerabilities or services of the
        hostname.

        Hostname/IP corroboration and service association confidence are
        therefore separate concepts.

        In particular:

            DNS -> IP

        does not mean:

            hostname -> every service observed on IP.

        If InternetDB does not report the investigated hostname on the
        IP, service association remains partial even when the IP has
        only one observed hostname. That hostname could simply be a
        different asset.

        IP sharing reduces service association confidence because other
        hostnames may use the same IP. CDN/proxy indicators are treated
        more gently: they reduce confidence in exclusive attribution
        of IP-level services, but they do not by themselves make the
        hostname's observed web service association weak.
        """

        observations = finding.exposure_observations

        if not observations:

            return self._score_legacy_exposure(
                finding,
            )

        score = 0.0
        rationale = []

        relationship_score, relationship_details = (
            self._per_ip_relationship_score(
                observations,
            )
        )

        score += relationship_score

        rationale.append(
            f"Hostname/IP relationship strength: "
            f"+{relationship_score:.1f}/35."
        )

        rationale.extend(
            relationship_details,
        )

        service_relevance, service_details = (
            self._per_ip_raw_service_relevance(
                observations,
            )
        )

        service_points = (
            service_relevance
            * 0.25
        )

        score += service_points

        rationale.append(
            f"Observed service surface "
            f"{service_relevance:.1f}/100: "
            f"+{service_points:.1f}/25."
        )

        rationale.extend(
            service_details,
        )

        association = (
            self._per_ip_service_association(
                observations,
            )
        )

        association_points = (
            association
            * 20.0
        )

        finding.service_association_confidence = round(
            association,
            2,
        )

        score += association_points

        rationale.append(
            f"Per-IP service association confidence "
            f"{association:.2f}: "
            f"+{association_points:.1f}/20."
        )

        # Explain service association confidence at IP granularity.
        # This is particularly useful for Reporting and for auditing
        # why a shared IP was treated conservatively.
        for observation in observations:

            association_factor = (
                self._observation_service_association_factor(
                    observation,
                )
            )

            relationship_text = (
                "hostname corroborated by InternetDB"
                if (
                    observation.relationship_strength
                    == CorrelationStrength.CORROBORATED
                )
                else
                "hostname not corroborated by InternetDB"
            )

            # An empty hostname list means InternetDB did not provide
            # enough information to determine IP sharing.
            sharing_text = (
                str(observation.ip_sharing)
                if observation.hostnames
                else "unknown"
            )

            rationale.append(
                f"IP {observation.ip_address}: "
                f"service association confidence="
                f"{association_factor:.2f} "
                f"({relationship_text}; "
                f"IP sharing={sharing_text})."
            )

        context = (
            self._per_ip_exposure_context(
                observations,
            )
        )

        context_points = (
            context
            * 0.10
        )

        score += context_points

        rationale.append(
            f"Per-IP contextual exposure "
            f"{context:.1f}/100: "
            f"+{context_points:.1f}/10."
        )

        breadth = (
            self._per_ip_breadth(
                observations,
            )
        )

        score += breadth

        rationale.append(
            f"Per-IP port breadth contribution: "
            f"+{breadth:.1f}/10."
        )

        strongest_relationship = (
            self._finding_strength(
                finding,
            )
        )

        # A potential hostname/IP relationship must not become
        # MEDIUM merely because InternetDB observed many services
        # on the associated IP.
        if (
            strongest_relationship
            == CorrelationStrength.POTENTIAL
            and score >= self.MEDIUM_THRESHOLD
        ):

            finding.priority_raw_score = round(
                score,
                1,
            )

            score = 49.9

            rationale.append(
                "Potential exposure is capped below MEDIUM because "
                "the hostname-to-IP relationship is not independently "
                "corroborated. IP-level services therefore cannot "
                "establish a medium-or-higher hostname exposure finding "
                "on their own."
            )

        # A corroborated hostname/IP relationship is strong evidence that
        # the hostname uses the IP, but it does not prove exclusive
        # ownership of every IP-level service. Shared hosting can therefore
        # block HIGH when the strongest service association is weak.
        # CDN/proxy infrastructure is already handled more gently by the
        # association factor above and does not receive an automatic HIGH
        # penalty merely for being a CDN.
        best_service_association = max(
            (
                self._observation_service_association_factor(
                    observation,
                )
                for observation in observations
            ),
            default=0.0,
        )

        if (
            score >= self.HIGH_THRESHOLD
            and best_service_association < 0.85
        ):

            finding.priority_raw_score = round(
                score,
                1,
            )

            # The purpose of this rule is classification, not score
            # manipulation: an exposure whose strongest service
            # association confidence is insufficient cannot be
            # classified as HIGH.
            score = 79.9

            rationale.append(
                "High-priority exposure is capped below HIGH because "
                f"the strongest per-IP service association confidence "
                f"is only {best_service_association:.2f}. InternetDB "
                "observes IP-level infrastructure rather than proving "
                "exclusive ownership of every service on the hostname's "
                "associated IP."
            )

        return score, rationale

    def _score_legacy_exposure(
        self,
        finding: Finding,
    ) -> tuple[float, list[str]]:
        """
        Conservative compatibility path for exposure findings produced
        without explicit per-IP observations.

        Legacy findings cannot preserve exact hostname corroboration,
        so a low sharing count alone is never treated as proof that
        services belong to the hostname.
        """

        strength = self._finding_strength(
            finding,
        )

        relationship_points = (
            self._relationship_points(
                strength,
                direct=30.0,
                corroborated=35.0,
                potential=15.0,
            )
        )

        ports = self._signal_values(
            finding,
            "ports",
        )

        raw_service_relevance = (
            self._port_service_relevance(
                ports,
            )
        )

        association_factor = (
            self._service_association_factor(
                finding,
            )
        )

        service_points = (
            raw_service_relevance
            * 0.25
        )

        association_points = (
            association_factor
            * 20.0
        )

        finding.service_association_confidence = round(
            association_factor,
            2,
        )

        context = (
            self._exposure_context(
                finding,
            )
        )

        context_points = (
            context
            * 0.10
        )

        breadth_points = (
            self._port_breadth_points(
                ports,
            )
        )

        score = (
            relationship_points
            + service_points
            + association_points
            + context_points
            + breadth_points
        )

        rationale = [
            (
                f"Hostname/IP relationship "
                f"{strength.value if strength else 'Unknown'}: "
                f"+{relationship_points:.1f}/35."
            ),
            (
                f"Observed service surface "
                f"{raw_service_relevance:.1f}/100: "
                f"+{service_points:.1f}/25."
            ),
            (
                f"Service association confidence factor "
                f"{association_factor:.2f}: "
                f"+{association_points:.1f}/20."
            ),
            (
                f"Contextual exposure "
                f"{context:.1f}/100: "
                f"+{context_points:.1f}/10."
            ),
            (
                f"Port breadth "
                f"{len(set(ports))} distinct port(s): "
                f"+{breadth_points:.1f}/10."
            ),
        ]

        if (
            strength == CorrelationStrength.POTENTIAL
            and score >= self.MEDIUM_THRESHOLD
        ):

            finding.priority_raw_score = round(
                score,
                1,
            )

            score = 49.9

            rationale.append(
                "Potential exposure is capped below MEDIUM because "
                "the hostname-to-IP relationship is not independently "
                "corroborated."
            )

        return score, rationale

    @classmethod
    def _per_ip_relationship_score(
        cls,
        observations,
    ) -> tuple[float, list[str]]:
        """
        Score hostname-to-IP relationship evidence.

        The strongest relationship is the primary signal. Additional IPs
        contribute with diminishing returns and the total is capped at
        the relationship component's 35 points.

        This score says how well the hostname is related to the observed
        IP exposure. It does not say that the IP's services belong to
        the hostname.
        """

        relationship_points = {
            CorrelationStrength.POTENTIAL: 15.0,
            CorrelationStrength.DIRECT: 30.0,
            CorrelationStrength.CORROBORATED: 35.0,
        }

        values = [
            relationship_points.get(
                observation.relationship_strength,
                0.0,
            )
            for observation in observations
        ]

        values.sort(
            reverse=True,
        )

        if not values:
            return 0.0, []

        score = values[0]

        multiplier = 0.25

        for value in values[1:]:

            score += (
                value
                * multiplier
            )

            multiplier *= 0.5

        score = min(
            score,
            35.0,
        )

        counts = {
            CorrelationStrength.CORROBORATED: 0,
            CorrelationStrength.DIRECT: 0,
            CorrelationStrength.POTENTIAL: 0,
        }

        for observation in observations:

            if observation.relationship_strength in counts:

                counts[
                    observation.relationship_strength
                ] += 1

        details = []

        summary = ", ".join(
            (
                f"{strength.value.lower()}="
                f"{counts[strength]}"
            )
            for strength
            in (
                CorrelationStrength.CORROBORATED,
                CorrelationStrength.DIRECT,
                CorrelationStrength.POTENTIAL,
            )
            if counts[strength]
        )

        if summary:

            details.append(
                f"Per-IP hostname relationship: "
                f"{summary}."
            )

        return score, details

    @classmethod
    def _per_ip_raw_service_relevance(
        cls,
        observations,
    ) -> tuple[float, list[str]]:
        """
        Calculate service-surface relevance from observed ports without
        applying hostname service-association penalties.

        Service association confidence is scored separately. This prevents
        sharing or proxy/CDN evidence from being counted twice.
        """

        ranked = []
        details = []

        for observation in observations:

            raw = cls._port_service_relevance(
                observation.ports,
            )

            ranked.append(
                raw,
            )

            details.append(
                f"IP {observation.ip_address}: "
                f"{len(set(observation.ports))} port(s), "
                f"observed service surface={raw:.1f}/100."
            )

        ranked.sort(
            reverse=True,
        )

        if not ranked:
            return 0.0, details

        aggregate = ranked[0]

        multiplier = 0.25

        for value in ranked[1:]:

            aggregate += (
                value
                * multiplier
            )

            multiplier *= 0.5

        return (
            min(
                aggregate,
                100.0,
            ),
            details,
        )

    @classmethod
    def _per_ip_service_association(
        cls,
        observations,
    ) -> float:
        """
        Aggregate how strongly the observed IP-level services can be
        associated with the investigated hostname.

        The weighting follows observed service surface: an IP carrying
        the larger service surface has more influence.

        Crucially, the service association factor itself is based on
        explicit hostname corroboration, sharing and proxy/CDN context.
        It is not inferred from sharing alone.
        """

        weighted = 0.0
        weight = 0.0
        fallback_values = []

        for observation in observations:

            factor = (
                cls._observation_service_association_factor(
                    observation,
                )
            )

            raw_relevance = (
                cls._port_service_relevance(
                    observation.ports,
                )
            )

            if raw_relevance > 0.0:

                weighted += (
                    raw_relevance
                    * factor
                )

                weight += raw_relevance

            else:

                fallback_values.append(
                    factor,
                )

        if weight > 0.0:

            return round(
                weighted / weight,
                2,
            )

        if fallback_values:

            return round(
                sum(fallback_values)
                / len(fallback_values),
                2,
            )

        return 0.0

    @classmethod
    def _per_ip_exposure_context(
        cls,
        observations,
    ) -> float:
        """
        Use the strongest contextual observation rather than adding
        contextual information from every IP linearly.

        IP-level CVEs are intentionally excluded: they remain visible
        as observations but are not treated as vulnerabilities of the
        hostname.
        """

        if not observations:
            return 0.0

        return max(
            cls._observation_context(
                observation,
            )
            for observation in observations
        )

    @classmethod
    def _per_ip_breadth(
        cls,
        observations,
    ) -> float:
        """
        Aggregate port breadth per IP with diminishing returns.
        """

        values = sorted(
            (
                cls._port_breadth_points(
                    observation.ports,
                )
                for observation in observations
            ),
            reverse=True,
        )

        if not values:
            return 0.0

        aggregate = values[0]

        multiplier = 0.25

        for value in values[1:]:

            aggregate += (
                value
                * multiplier
            )

            multiplier *= 0.5

        return min(
            aggregate,
            10.0,
        )

    @classmethod
    def _observation_service_association_factor(
        cls,
        observation,
    ) -> float:
        """
        Calculate service association confidence between IP-level
        observations and the investigated hostname.

        Explicit hostname corroboration from InternetDB is the primary
        evidence.

        CORROBORATED:
            InternetDB explicitly observed the investigated hostname on
            the IP. Base service association confidence is high, but
            this does not prove ownership of every service observed on
            the IP.

        POTENTIAL:
            DNS associated the hostname with the IP, but InternetDB did
            not report the hostname on that IP. The IP-level services
            therefore remain only partially associated with the hostname.

        A low number of observed hostnames is not enough by itself:
        one observed hostname may be a completely different asset.

        IP sharing reduces service association confidence. CDN/proxy
        indicators are a milder adjustment because they limit confidence
        in exclusive attribution without making the hostname's observed
        web-service association inherently weak.
        """

        if (
            observation.relationship_strength
            == CorrelationStrength.CORROBORATED
        ):

            # Corroboration provides strong evidence that the hostname is
            # associated with the IP, but it does not prove ownership of
            # every service observed on that IP.
            base_factor = 0.95

        else:

            # DNS can establish hostname -> IP, but absence of the
            # hostname from InternetDB means service association remains
            # uncertain.
            base_factor = 0.50

        if observation.hostnames:

            sharing = max(
                observation.ip_sharing,
                1,
            )

            if sharing <= 2:

                sharing_factor = 1.0

            elif sharing <= 5:

                sharing_factor = 0.90

            elif sharing <= 9:

                sharing_factor = 0.80

            else:

                sharing_factor = 0.70

        else:

            # No hostname list means unknown sharing. It is not evidence
            # of a dedicated IP.
            sharing_factor = 0.75

        contextual_text = " ".join(
            str(value)
            for value
            in (
                *observation.cpes,
                *observation.tags,
            )
        ).lower()

        proxy_indicators = (
            "cloudflare",
            "fastly",
            "akamai",
            "cloudfront",
            "incapsula",
            "imperva",
            "cdn",
        )

        proxy_factor = 1.0

        if any(
            indicator in contextual_text
            for indicator
            in proxy_indicators
        ):
            # A CDN/proxy is shared delivery infrastructure, so it lowers
            # confidence that every IP-level service is exclusive to the
            # investigated hostname. It should not, however, turn a
            # corroborated 80/443 hostname into a weak service association.
            proxy_factor = 0.90

        return (
            base_factor
            * sharing_factor
            * proxy_factor
        )

    @classmethod
    def _observation_context(
        cls,
        observation,
    ) -> float:
        """
        Score contextual information for one IP observation.

        CVEs observed by InternetDB are deliberately not included.
        They remain available to the finding as raw observations but
        cannot increase hostname priority as though they were attributed
        vulnerabilities.

        Hostname sharing is considered only when InternetDB actually
        reports hostnames for the IP.
        """

        score = 0.0

        if observation.tags:
            score += 20.0

        if observation.cpes:
            score += 20.0

        if observation.hostnames:

            sharing = max(
                observation.ip_sharing,
                1,
            )

            if sharing <= 2:

                score += 10.0

            elif sharing >= 10:

                score -= 10.0

            elif sharing >= 5:

                score -= 5.0

        return max(
            0.0,
            min(
                score,
                100.0,
            ),
        )

    @staticmethod
    def _port_service_relevance(
        ports: list[int],
    ) -> float:
        """
        Estimate investigative relevance of observed ports.

        The score is intentionally bounded and based on service breadth,
        not on exploitability.
        """

        if not ports:
            return 0.0

        unique_ports = set(
            ports,
        )

        score = 0.0

        high_interest_ports = {
            21,
            22,
            23,
            25,
            53,
            110,
            111,
            139,
            143,
            389,
            445,
            465,
            587,
            636,
            993,
            995,
            1433,
            1521,
            2049,
            2375,
            3306,
            3389,
            5432,
            5900,
            6379,
            6443,
            8000,
            8008,
            8080,
            8081,
            8443,
            8888,
            9000,
            9200,
            27017,
        }

        standard_web_ports = {
            80,
            443,
        }

        for port in unique_ports:

            if port in high_interest_ports:

                score += 2.5

            elif port in standard_web_ports:

                score += 1.5

            elif port < 1024:

                score += 1.0

            elif port < 10000:

                score += 0.75

            else:

                score += 0.5

        return (
            min(
                score,
                10.0,
            )
            * 10.0
        )

    @staticmethod
    def _port_breadth_points(
        ports: list[int],
    ) -> float:
        """
        Give a diminishing-return bonus for multiple services.

        Breadth is capped at ten points and therefore cannot dominate
        the exposure score.
        """

        count = len(
            set(ports),
        )

        if count <= 0:
            return 0.0

        if count == 1:
            return 1.0

        if count == 2:
            return 2.5

        if count == 3:
            return 4.0

        if count == 4:
            return 5.0

        if count == 5:
            return 6.0

        if count == 6:
            return 6.8

        if count == 7:
            return 7.5

        if count == 8:
            return 8.0

        if count == 9:
            return 8.5

        if count == 10:
            return 9.0

        return 10.0

    @classmethod
    def _service_association_factor(
        cls,
        finding: Finding,
    ) -> float:
        """
        Conservative compatibility fallback for exposure findings
        without explicit per-IP observations.

        Legacy findings do not preserve the exact InternetDB hostname
        corroboration state, so a low sharing count cannot establish
        full service association.
        """

        sharing = cls._signal_number(
            finding,
            "max_ip_sharing",
        )

        if sharing is None:

            sharing_factor = 0.75

        elif sharing <= 2:

            sharing_factor = 1.0

        elif sharing <= 5:

            sharing_factor = 0.90

        elif sharing <= 9:

            sharing_factor = 0.80

        else:

            sharing_factor = 0.70

        contextual_text = (
            f"{cls._signal(finding, 'cpes') or ''} "
            f"{cls._signal(finding, 'tags') or ''}"
        ).lower()

        proxy_indicators = (
            "cloudflare",
            "fastly",
            "akamai",
            "cloudfront",
            "incapsula",
            "imperva",
            "cdn",
        )

        proxy_factor = 1.0

        if any(
            indicator in contextual_text
            for indicator
            in proxy_indicators
        ):

            # Match the explicit per-IP model: CDN/proxy reduces
            # exclusive attribution confidence, but is not treated as
            # proof that the observed web service is weakly associated.
            proxy_factor = 0.90

        return (
            0.50
            * sharing_factor
            * proxy_factor
        )

    @classmethod
    def _exposure_context(
        cls,
        finding: Finding,
    ) -> float:
        """
        Conservative compatibility context for legacy findings.

        Observed InternetDB CVEs are not scored as hostname
        vulnerabilities.
        """

        score = 0.0

        if cls._has_signal(
            finding,
            "tags",
        ):

            score += 20.0

        if cls._has_signal(
            finding,
            "cpes",
        ):

            score += 20.0

        sharing = cls._signal_number(
            finding,
            "max_ip_sharing",
        )

        if sharing is not None:

            if sharing <= 2:

                score += 10.0

            elif sharing >= 10:

                score -= 10.0

            elif sharing >= 5:

                score -= 5.0

        return max(
            0.0,
            min(
                score,
                100.0,
            ),
        )

    # ------------------------------------------------------------------
    # Historical
    # ------------------------------------------------------------------

    def _score_historical(
        self,
        finding: Finding,
    ) -> tuple[float, list[str]]:
        """
        Historical surface scoring.

        Recency is deliberately absent because the current Wayback
        collector does not provide an archive timestamp.

        Evidence quality:       20
        Resource sensitivity:   30
        Current corroboration:  50

        Without explicit current corroboration, a historical-only
        finding cannot reach MEDIUM.
        """

        evidence_quality = (
            self._evidence_quality(
                finding,
            )
        )

        sensitivity = (
            self._historical_sensitivity(
                finding,
            )
        )

        current_relation = (
            self._current_relation_score(
                finding,
            )
        )

        score = (
            evidence_quality * 0.20
            + sensitivity * 0.30
            + current_relation * 0.50
        )

        rationale = [
            (
                f"Evidence quality "
                f"{evidence_quality:.1f}/100: "
                f"+{evidence_quality * 0.20:.1f}/20."
            ),
            (
                f"Resource sensitivity "
                f"{sensitivity:.1f}/100: "
                f"+{sensitivity * 0.30:.1f}/30."
            ),
            (
                f"Current corroboration "
                f"{current_relation:.1f}/100: "
                f"+{current_relation * 0.50:.1f}/50."
            ),
            (
                "Archive recency is not scored because the "
                "current Wayback collector does not provide "
                "a timestamp."
            ),
        ]

        if current_relation <= 0.0:

            finding.priority_raw_score = round(
                score,
                1,
            )

            score = min(
                score,
                49.9,
            )

            rationale.append(
                "Historical-only finding is capped below MEDIUM "
                "because no current corroborating relationship "
                "is available."
            )

        return score, rationale

    @classmethod
    def _historical_sensitivity(
        cls,
        finding: Finding,
    ) -> float:
        """Score investigative sensitivity of a historical URL."""

        raw_url = (
            cls._signal(
                finding,
                "historical_url",
            )
            or ""
        ).strip().lower()

        if not raw_url:
            return 0.0

        parsed = urlparse(
            raw_url,
        )

        path = (
            parsed.path
            or raw_url
        ).rstrip("/")

        if not path:
            path = "/"

        path = (
            "/"
            + path.lstrip("/")
        )

        high_sensitivity = (
            "/admin",
            "/administrator",
            "/login",
            "/signin",
            "/graphql",
            "/swagger",
            "/api",
            "/manage",
            "/management",
            "/debug",
            "/actuator",
        )

        low_sensitivity = (
            "/robots.txt",
            "/sitemap.xml",
            "/favicon.ico",
        )

        if any(
            path == prefix
            or path.startswith(
                prefix + "/",
            )
            for prefix
            in high_sensitivity
        ):

            return 100.0

        if any(
            path == prefix
            for prefix
            in low_sensitivity
        ):

            return 35.0

        return 60.0

    @classmethod
    def _current_relation_score(
        cls,
        finding: Finding,
    ) -> float:
        """Score explicit current relationships only."""

        current_relationships = {
            "current_web_resource",
            "current_surface",
            "current_exposure",
        }

        best = 0.0

        for correlation in finding.correlations:

            if (
                correlation.relationship
                not in current_relationships
            ):
                continue

            if (
                correlation.strength
                == CorrelationStrength.CORROBORATED
            ):

                best = max(
                    best,
                    100.0,
                )

            elif (
                correlation.strength
                == CorrelationStrength.DIRECT
            ):

                best = max(
                    best,
                    80.0,
                )

            elif (
                correlation.strength
                == CorrelationStrength.POTENTIAL
            ):

                best = max(
                    best,
                    50.0,
                )

        return best

    # ------------------------------------------------------------------
    # Repositories
    # ------------------------------------------------------------------

    def _score_repository(
        self,
        target: Target,
        finding: Finding,
    ) -> tuple[float, list[str]]:
        """
        Repository scoring.

        Potential GitHub associations remain below MEDIUM because
        search relevance does not establish ownership.
        """

        strength = self._finding_strength(
            finding,
        )

        relationship_points = (
            self._relationship_points(
                strength,
                direct=30.0,
                corroborated=35.0,
                potential=15.0,
            )
        )

        evidence_quality = (
            self._evidence_quality(
                finding,
            )
        )

        evidence_points = (
            evidence_quality * 0.30
        )

        confidence = (
            self._confidence(
                finding.confidence,
            )
        )

        confidence_points = (
            confidence * 25.0
        )

        context = (
            self._repository_context(
                finding,
            )
        )

        context_points = (
            context * 0.10
        )

        score = (
            relationship_points
            + evidence_points
            + confidence_points
            + context_points
        )

        rationale = [
            (
                f"Repository relationship "
                f"{strength.value if strength else 'Unknown'}: "
                f"+{relationship_points:.1f}/35."
            ),
            (
                f"Independent evidence quality "
                f"{evidence_quality:.1f}/100: "
                f"+{evidence_points:.1f}/30."
            ),
            (
                f"Finding confidence "
                f"{confidence:.2f}: "
                f"+{confidence_points:.1f}/25."
            ),
            (
                f"Repository context "
                f"{context:.1f}/100: "
                f"+{context_points:.1f}/10."
            ),
        ]

        if strength == CorrelationStrength.POTENTIAL:

            finding.priority_raw_score = round(
                score,
                1,
            )

            score = min(
                score,
                49.9,
            )

            rationale.append(
                "Potential repository association is capped "
                "below MEDIUM because ownership is not "
                "established by the current evidence."
            )

        return score, rationale

    # ------------------------------------------------------------------
    # Generic
    # ------------------------------------------------------------------

    def _repository_context(
        self,
        finding: Finding,
    ) -> float:
        """Score additional repository context."""

        score = 0.0

        repository = (
            self._signal(
                finding,
                "repository",
            )
            or ""
        ).lower()

        if repository:

            score += 40.0

        target = (
            self._signal(
                finding,
                "target",
            )
            or ""
        ).lower()

        if target:

            score += 20.0

        if self._has_signal(
            finding,
            "ownership",
        ):

            score += 40.0

        return max(
            0.0,
            min(
                score,
                100.0,
            ),
        )

    def _score_generic(
        self,
        finding: Finding,
    ) -> tuple[float, list[str]]:
        """Conservative fallback scoring."""

        strength = self._finding_strength(
            finding,
        )

        relationship_points = (
            self._relationship_points(
                strength,
                direct=30.0,
                corroborated=35.0,
                potential=15.0,
            )
        )

        confidence = self._confidence(
            finding.confidence,
        )

        confidence_points = (
            confidence * 30.0
        )

        evidence_quality = (
            self._evidence_quality(
                finding,
            )
        )

        evidence_points = (
            evidence_quality * 0.20
        )

        score = (
            relationship_points
            + confidence_points
            + evidence_points
        )

        rationale = [
            (
                f"Finding relationship "
                f"{strength.value if strength else 'Unknown'}: "
                f"+{relationship_points:.1f}/35."
            ),
            (
                f"Finding confidence "
                f"{confidence:.2f}: "
                f"+{confidence_points:.1f}/30."
            ),
            (
                f"Evidence quality "
                f"{evidence_quality:.1f}/100: "
                f"+{evidence_points:.1f}/20."
            ),
        ]

        return score, rationale

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_strength(
        finding: Finding,
    ) -> CorrelationStrength | None:
        """Return the strongest known finding relationship."""

        if finding.strength is not None:
            return finding.strength

        ranking = {
            CorrelationStrength.POTENTIAL: 1,
            CorrelationStrength.DIRECT: 2,
            CorrelationStrength.CORROBORATED: 3,
        }

        strongest = None

        for correlation in finding.correlations:

            if (
                strongest is None
                or ranking.get(
                    correlation.strength,
                    0,
                )
                >
                ranking.get(
                    strongest,
                    0,
                )
            ):

                strongest = correlation.strength

        return strongest

    @staticmethod
    def _relationship_points(
        strength: CorrelationStrength | None,
        direct: float,
        corroborated: float,
        potential: float,
    ) -> float:
        """Convert relationship strength into bounded points."""

        if strength == CorrelationStrength.CORROBORATED:
            return corroborated

        if strength == CorrelationStrength.DIRECT:
            return direct

        if strength == CorrelationStrength.POTENTIAL:
            return potential

        return 0.0

    @staticmethod
    def _confidence(
        confidence: float | None,
    ) -> float:
        """Normalise confidence into the 0-1 range."""

        try:

            value = float(
                confidence,
            )

        except (
            TypeError,
            ValueError,
        ):

            return 0.0

        # Findings produced by Intelligence should already be normalised,
        # but keeping this helper tolerant prevents invalid values from
        # corrupting the final score.
        if value > 1.0:
            value /= 100.0

        return max(
            0.0,
            min(
                1.0,
                value,
            ),
        )

    @staticmethod
    def _signal(
        finding: Finding,
        signal_type: str,
    ) -> str | None:
        """Return the first signal matching a type."""

        for signal in finding.signals:

            if signal.type == signal_type:

                return signal.value

        return None

    @classmethod
    def _has_signal(
        cls,
        finding: Finding,
        signal_type: str,
    ) -> bool:
        """Return whether a finding contains a non-empty signal."""

        value = cls._signal(
            finding,
            signal_type,
        )

        return bool(
            value
            and str(value).strip(),
        )

    @classmethod
    def _signal_number(
        cls,
        finding: Finding,
        signal_type: str,
    ) -> float | None:

        value = cls._signal(
            finding,
            signal_type,
        )

        # Compatibility with findings generated before the signal was
        # renamed to make its aggregated meaning explicit.
        if (
            not value
            and signal_type == "max_ip_sharing"
        ):
            value = cls._signal(
                finding,
                "ip_sharing",
            )

        if not value:
            return None

        try:

            return float(
                str(value)
                .strip()
                .split(
                    " ",
                    1,
                )[0],
            )

        except ValueError:

            return None

    @classmethod
    def _signal_values(
        cls,
        finding: Finding,
        signal_type: str,
    ) -> list[int]:
        """Parse a comma-separated numeric signal."""

        value = cls._signal(
            finding,
            signal_type,
        )

        if not value:
            return []

        values = []

        for item in str(value).split(","):

            item = item.strip()

            if not item:
                continue

            try:

                values.append(
                    int(item),
                )

            except ValueError:

                continue

        return values

    @staticmethod
    def _normalise_cvss(
        value: float | None,
    ) -> float | None:
        """Normalise a CVSS value into the 0-10 range."""

        if value is None:
            return None

        try:

            result = float(
                value,
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

        return max(
            0.0,
            min(
                10.0,
                result,
            ),
        )

    @classmethod
    def _evidence_quality(
        cls,
        finding: Finding,
    ) -> float:
        """
        Estimate evidence quality from independent source types.

        Several evidence records from the same source are not
        independent corroboration and therefore do not inflate
        the score repeatedly.
        """

        sources = {
            getattr(
                evidence.source,
                "value",
                str(evidence.source),
            )
            for evidence in finding.evidence
        }

        count = len(
            sources,
        )

        if count <= 0:
            return 0.0

        if count == 1:
            return 50.0

        if count == 2:
            return 70.0

        if count == 3:
            return 85.0

        if count == 4:
            return 92.0

        return 100.0

    # ------------------------------------------------------------------
    # Priority classification
    # ------------------------------------------------------------------

    @classmethod
    def _priority_for_score(
        cls,
        score: float,
    ) -> InvestigationPriority:
        """Map a numerical score to a qualitative priority."""

        if score >= cls.HIGH_THRESHOLD:

            return InvestigationPriority.HIGH

        if score >= cls.MEDIUM_THRESHOLD:

            return InvestigationPriority.MEDIUM

        if score >= cls.LOW_THRESHOLD:

            return InvestigationPriority.LOW

        return InvestigationPriority.INFO