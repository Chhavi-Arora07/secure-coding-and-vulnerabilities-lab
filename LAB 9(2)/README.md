# Lab 20 - Static analysis with SonarQube and Semgrep

- `vaultapp/app.py`      intentionally vulnerable file-based app (stdlib only). Do not deploy.
- `semgrep/rules.yaml`   custom Semgrep rules
- `sonar/sonar-project.properties`  SonarQube scanner config (token via `SONAR_TOKEN` env var)
- `dyn_tests.py`         dynamic tests (stand-in for Question 1), writes `evidence/dynamic_results.json`
- `run_scans.sh`         runs Semgrep, sonar-scanner and the dynamic tests, saving raw output to `evidence/`
- `Lab20_Static_Analysis_Report.pdf`  the report

Run `./run_scans.sh` and compare the raw output with the report's Sections 5-6 before submitting.
