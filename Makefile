# HexaCore lifecycle (Brain/07 §8). Phase-0 targets are implemented; infra targets are
# placeholders until docker-compose / Kali runner land.

.PHONY: run test ingest up down kali-build runner-check serve engage kill report logs

run:             ## one command: install everything (deps, tools, LLM, console) then launch
	./hexacore.sh

test:            ## run all unit tests
	python -m pytest -q

serve:           ## run the API + WebSocket server (http://localhost:8000, docs at /docs)
	python serve.py --reload

console:         ## run the operator dashboard (http://localhost:5173) — needs `make serve` too
	cd console && npm install && npm run dev

console-build:   ## type-check + production build of the console
	cd console && npm install && npm run build

ingest:          ## build skills-validation-report.md + skills-index.json from Heart/
	python skills/skillsvc/ingest.py --heart Heart

up:              ## start platform datastores (postgres, redis, minio)
	docker compose -f infra/docker-compose.yml up -d

down:            ## stop platform
	docker compose -f infra/docker-compose.yml down

kali-build:      ## build the Kali tool-runner image (Docker backend)
	docker build -t hexacore/kali-tools:latest infra/kali

runner-check:    ## verify the configured tool runner (set HEXACORE_RUNNER_BACKEND / HEXACORE_VM_HOST)
	PYTHONPATH=tools python -m hexacore_tools.backends.cli

engage:          ## run an engagement from a scope file: make engage SCOPE=engagements/<name>.yaml
	python engage.py --scope $(SCOPE)

kill:            ## trip the kill switch for an engagement — TODO
	@echo "TODO: make kill ENG=<id>"

report:          ## (re)generate a report — TODO Phase 1
	@echo "TODO"

logs:            ## tail platform logs — TODO
	@echo "TODO"
