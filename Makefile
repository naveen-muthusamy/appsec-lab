.PHONY: all secrets sast triage clean

all:
	./run.sh

secrets:
	python3 scripts/scan_secrets.py

sast:
	python3 scripts/scan_sast.py

triage:
	python3 scripts/triage_report.py

clean:
	rm -f artifacts/*.json artifacts/*.sarif artifacts/*.md
