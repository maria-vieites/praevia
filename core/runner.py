"""
Praevia execution runner.
"""

import io
from contextlib import redirect_stdout

from collectors.base_collector import BaseCollector
from correlation.correlation_engine import CorrelationEngine
from intelligence.intelligence_engine import IntelligenceEngine
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target
from priorisation.priorisation_engine import PriorisationEngine


class Runner:
    """
    Coordinates the execution of the passive reconnaissance workflow.
    """

    def __init__(
        self,
        collectors: list[BaseCollector],
    ) -> None:
        """
        Initialises the runner with the configured collectors.
        """

        self._collectors = collectors
        self._correlation_engine = CorrelationEngine()
        self._intelligence_engine = IntelligenceEngine()
        self._priorisation_engine = PriorisationEngine()
        self.execution_logs: list[str] = []

    def run(
        self,
        target: Target,
        verbose: bool = False,
    ) -> ReconnaissanceData:
        """
        Executes the passive reconnaissance workflow.

        Collector console output is captured as execution information so
        that the workflow does not write development output directly to
        stdout. Verbose callers may display the captured information.
        """

        data = ReconnaissanceData()

        self.execution_logs = []

        for collector in self._collectors:

            buffer = io.StringIO()

            with redirect_stdout(
                buffer,
            ):

                collector.collect(
                    target,
                    data,
                )

            output = buffer.getvalue().strip()

            if output:

                self.execution_logs.append(
                    f"{collector.name}:\n{output}"
                )

            elif verbose:

                self.execution_logs.append(
                    f"{collector.name}: completed."
                )

        self._correlation_engine.correlate(
            target,
            data,
        )

        self._intelligence_engine.analyse(
            target,
            data,
        )

        self._priorisation_engine.prioritise(
            target,
            data,
        )

        return data