# Contributing to ThreatPath AI

1. **No Fake Findings or Mock Production Telemetry**: Never hardcode fabricated CVEs or claim an uninstalled external tool succeeded.
2. **Safe Testing Only**: Use only harmless test fixtures (such as the official 68-byte EICAR string in `sample_data/eicar_test.txt` and `sample_data/demo_vulnerable_app/`). Never introduce real malware or scan unauthorized external hosts.
3. **Run All Tests Before Submitting**:
   ```bash
   python3 ai-agent-service/tests/test_threatpath.py
   ```
