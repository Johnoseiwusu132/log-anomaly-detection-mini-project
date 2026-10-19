import tempfile
import unittest
from pathlib import Path
from analyze_logs import analyze_logs


class AnalyzeLogsTests(unittest.TestCase):
    def make_csv(self, content: str) -> str:
        tmp = tempfile.NamedTemporaryFile(mode="w", newline="", encoding="utf-8", suffix=".csv", delete=False)
        tmp.write(content)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_flags_repeated_failed_logins(self):
        path = self.make_csv(
            "timestamp,source_ip,event,level\n"
            "t1,203.0.113.4,failed_login,warning\n"
            "t2,203.0.113.4,failed_login,warning\n"
            "t3,203.0.113.4,failed_login,warning\n"
        )
        report = analyze_logs(path)
        self.assertEqual(report["repeated_failed_logins"], {"203.0.113.4": 3})

    def test_does_not_flag_below_threshold(self):
        path = self.make_csv(
            "timestamp,source_ip,event,level\n"
            "t1,203.0.113.4,failed_login,warning\n"
            "t2,203.0.113.4,failed_login,warning\n"
        )
        self.assertEqual(analyze_logs(path)["repeated_failed_logins"], {})

    def test_flags_error_spike(self):
        path = self.make_csv(
            "timestamp,source_ip,event,level\n"
            "t1,203.0.113.5,crash,error\n"
            "t2,203.0.113.5,crash,error\n"
            "t3,203.0.113.5,crash,error\n"
        )
        self.assertEqual(analyze_logs(path)["elevated_error_levels"], {"error": 3})

    def test_rejects_missing_columns(self):
        path = self.make_csv("timestamp,event\nt1,failed_login\n")
        with self.assertRaises(ValueError):
            analyze_logs(path)

    def test_rejects_invalid_threshold(self):
        path = self.make_csv("timestamp,source_ip,event,level\nt1,203.0.113.1,login_success,info\n")
        with self.assertRaises(ValueError):
            analyze_logs(path, failed_login_threshold=0)


if __name__ == "__main__":
    unittest.main()
