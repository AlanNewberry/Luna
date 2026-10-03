import unittest
from dataclasses import asdict

from luna.core.findings import Finding


class TestFinding(unittest.TestCase):
    def test_creation_with_all_fields(self):
        finding = Finding(
            id="TEST-001",
            title="Test finding",
            severity="High",
            description="A test finding for unit testing.",
            evidence="Test evidence",
            affected_resource="https://example.com/api",
            remediation="Fix the issue.",
            references=["https://example.com/ref"],
        )
        self.assertEqual(finding.id, "TEST-001")
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.references, ["https://example.com/ref"])

    def test_creation_with_default_references(self):
        finding = Finding(
            id="TEST-002",
            title="Minimal finding",
            severity="Low",
            description="Finding with default references.",
            evidence="None",
            affected_resource="https://example.com",
            remediation="None needed.",
        )
        self.assertEqual(finding.references, [])

    def test_asdict_conversion(self):
        finding = Finding(
            id="TEST-003",
            title="Dict test",
            severity="Medium",
            description="Should serialize to dict.",
            evidence="Some evidence",
            affected_resource="https://example.com",
            remediation="Update config.",
            references=["https://owasp.org"],
        )
        data = asdict(finding)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["id"], "TEST-003")
        self.assertIn("references", data)


if __name__ == "__main__":
    unittest.main()
