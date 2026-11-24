#!/usr/bin/env bash
# Run both scanners and keep raw output as evidence.  Requires: semgrep, sonar-scanner, a running SonarQube.
set -e
mkdir -p evidence
semgrep --config semgrep/rules.yaml --config p/python --config p/owasp-top-ten \
        --json -o evidence/semgrep.json vaultapp/
semgrep --config semgrep/rules.yaml vaultapp/ | tee evidence/semgrep.txt
sonar-scanner -Dproject.settings=sonar/sonar-project.properties -Dsonar.token="$SONAR_TOKEN"
# export issues for the report:
curl -s -u "$SONAR_TOKEN:" "http://localhost:9000/api/issues/search?componentKeys=vaultapp-lab20&ps=500" \
     -o evidence/sonarqube_issues.json
python3 dyn_tests.py > evidence/dynamic_results.txt
