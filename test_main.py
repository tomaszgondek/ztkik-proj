import bz2
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import main


class InjectorTest(unittest.TestCase):
    def make_fixture(self, path: Path, records: int = 200) -> list[str]:
        lines = [f"{i * 10},U{(i % 8) + 1},C{(i % 24) + 1}\n" for i in range(records)]
        path.write_text("".join(lines), encoding="utf-8")
        return lines

    def test_plain_text_keeps_first_half_and_writes_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "in.txt", root / "out.txt"
            original = self.make_fixture(source)
            result = main.main(
                [
                    str(source), str(output), "--duration", "500",
                    "--automation-duration", "300", "--automation-interval", "50",
                    "--progress-every", "0",
                ]
            )
            self.assertEqual(result, 0)
            modified = output.read_text(encoding="utf-8").splitlines(keepends=True)
            self.assertEqual(modified[:100], original[:100])
            self.assertGreater(len(modified), len(original))
            timestamps = [int(line.split(",", 1)[0]) for line in modified]
            self.assertEqual(timestamps, sorted(timestamps))

            with Path(str(output) + ".ground_truth.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertGreater(len(rows), 0)
            self.assertEqual(
                {row["phase"] for row in rows},
                {
                    "account_takeover",
                    "lateral_movement",
                    "privilege_escalation",
                    "automated_spread",
                },
            )
            automated_rows = [row for row in rows if row["phase"] == "automated_spread"]
            burst_times = sorted({int(row["time"]) for row in automated_rows})
            self.assertEqual(len(burst_times), 6)
            self.assertEqual(
                [later - earlier for earlier, later in zip(burst_times, burst_times[1:])],
                [50] * 5,
            )
            self.assertTrue(
                all(
                    sum(int(row["time"]) == timestamp for row in automated_rows) == 18
                    for timestamp in burst_times
                )
            )
            metadata = json.loads(
                Path(str(output) + ".metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["unchanged_prefix_records"], 100)
            self.assertEqual(metadata["injected_events"], len(rows))
            self.assertEqual(metadata["automation_interval_seconds"], 50)
            self.assertEqual(metadata["automated_bursts"], 6)
            self.assertEqual(metadata["automation_period_seconds"], 86400)
            self.assertEqual(metadata["automated_windows"], 1)
            takeover_rows = [row for row in rows if row["phase"] == "account_takeover"]
            self.assertGreaterEqual(len(takeover_rows), 10)
            self.assertEqual(len({row["time"] for row in takeover_rows}), 1)
            self.assertTrue(
                set(metadata["victim_baseline_computers"]).isdisjoint(
                    {row["computer"] for row in takeover_rows}
                )
            )

    def test_bzip2_input_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "in.bz2", root / "out.bz2"
            lines = [f"{i * 10},U{(i % 8) + 1},C{(i % 24) + 1}\n" for i in range(200)]
            with bz2.open(source, "wt", encoding="utf-8") as handle:
                handle.writelines(lines)
            result = main.main(
                [
                    str(source), str(output), "--duration", "500",
                    "--automation-duration", "300", "--automation-interval", "50",
                    "--progress-every", "0",
                ]
            )
            self.assertEqual(result, 0)
            with bz2.open(output, "rt", encoding="utf-8") as handle:
                modified = handle.readlines()
            self.assertEqual(modified[:100], lines[:100])
            self.assertGreater(len(modified), len(lines))

    def test_no_arguments_uses_data_and_output_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir, output_dir = root / "data", root / "output"
            data_dir.mkdir()
            output_dir.mkdir()
            source = data_dir / "sample.txt"
            self.make_fixture(source)

            with mock.patch.object(main, "DATA_DIR", data_dir), mock.patch.object(
                main, "OUTPUT_DIR", output_dir
            ):
                result = main.main(
                    [
                        "--duration", "500", "--automation-duration", "300",
                        "--automation-interval", "50", "--progress-every", "0",
                    ]
                )

            self.assertEqual(result, 0)
            self.assertTrue((output_dir / "sample-modified.txt").is_file())
            self.assertTrue(
                (output_dir / "sample-modified.txt.ground_truth.csv").is_file()
            )
            self.assertTrue((output_dir / "sample-modified.txt.metadata.json").is_file())

    def test_automation_repeats_until_dataset_end(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "in.txt", root / "out.txt"
            self.make_fixture(source)

            result = main.main(
                [
                    str(source), str(output), "--duration", "500",
                    "--automation-duration", "200", "--automation-interval", "50",
                    "--automation-period", "400", "--progress-every", "0",
                ]
            )

            self.assertEqual(result, 0)
            metadata = json.loads(
                Path(str(output) + ".metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["automated_windows"], 2)
            self.assertEqual(metadata["automated_bursts"], 5)
            self.assertEqual(metadata["automation_campaign_end"], 1990)
            self.assertEqual(metadata["last_injected_timestamp"], 1950)


if __name__ == "__main__":
    unittest.main()
