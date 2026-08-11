import csv
import json
import tempfile
import unittest
from pathlib import Path

from dataset_analyzer import analyze_dataset


class DatasetAnalyzerTests(unittest.TestCase):
    def test_creates_reports_and_detects_conflicts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "payloads.csv"
            with source.open("w", newline="", encoding="utf-8") as target:
                writer = csv.writer(target)
                writer.writerow(["payload", "status code"])
                for index in range(120):
                    writer.writerow([f"select-{index}", 403 if index % 2 else 200])
                writer.writerow(["SELECT-1", 200])  # conflicts after normalization

            report = analyze_dataset(source, root / "Dataset Analysis")

            self.assertEqual(report["summary"]["total_rows"], 121)
            self.assertEqual(report["summary"]["conflicting_canonical_payloads"], 1)
            self.assertTrue((root / "Dataset Analysis" / "dataset_analysis.csv").exists())
            self.assertTrue((root / "Dataset Analysis" / "chunk_entropy.csv").exists())
            json_path = root / "Dataset Analysis" / "dataset_analysis.json"
            saved_report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_report["score"], report["score"])
            self.assertGreater(saved_report["file_entropy"]["whole_file_bits_per_byte"], 0)
            self.assertFalse(saved_report["attack_category_coverage"]["available"])

    def test_requires_recognized_columns(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "bad.csv"
            source.write_text("unknown,value\na,b\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_dataset(source, Path(temporary) / "output")


if __name__ == "__main__":
    unittest.main()
