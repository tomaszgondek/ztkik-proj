import tempfile
import unittest
from pathlib import Path

import analyze_logs


class AnalysisReportTest(unittest.TestCase):
    def test_detects_periodic_simultaneous_logons(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "modified.txt"
            report = root / "report.html"
            records: list[tuple[int, str, str]] = []

            # Baseline activity covering several hours.
            for hour in range(10):
                for index in range(20):
                    records.append((hour * 3600 + index * 30, f"U{index % 5}", f"C{index % 8}"))

            # Six periodic bursts: 12 computers at the same second every 5 minutes.
            for burst in range(6):
                timestamp = 11 * 3600 + burst * 300
                for host in range(12):
                    records.append((timestamp, "U_AUTO", f"C{100 + host}"))

            records.sort()
            source.write_text(
                "".join(f"{time},{user},{computer}\n" for time, user, computer in records),
                encoding="utf-8",
            )

            result = analyze_logs.main(
                [str(source), str(report), "--progress-every", "0"]
            )

            self.assertEqual(result, 0)
            content = report.read_text(encoding="utf-8")
            self.assertIn("U_AUTO", content)
            self.assertIn("00:05:00", content)
            self.assertIn("Wykryto silnie okresowe", content)
            self.assertIn("Dokładne kandydaty początku incydentu", content)
            self.assertIn("D+0 11:00:00", content)
            self.assertNotIn("ground_truth", content)


if __name__ == "__main__":
    unittest.main()
