"""
Praevia execution runner.
"""

from models.target import Target


class Runner:
    """
    Coordinates the execution of Praevia.
    """

    def __init__(self, target: Target) -> None:
        self.target = target

    def run(self) -> None:
        """
        Execute the Praevia workflow.
        """

        # Temporary output.
        print("Starting Praevia...")
        print(f"Target: {self.target.host}")