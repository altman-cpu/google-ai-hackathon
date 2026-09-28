# forge -- development tasks. Zero third-party dependencies; everything below
# runs against a bare Python 3.11+ interpreter.

PYTHON ?= python3
export PYTHONPATH := src:.
export SOURCE_DATE_EPOCH := 0
export FORGE_SEI_NETWORK ?= atlantic-2

INTENT ?= examples/scan-billing.intent.json
OUT    ?= .forge/out

.PHONY: help test check doctor catalog validate design build quote verify iceberg serve clean reproducible

help:
	@echo "forge targets"
	@echo "  make test          run the full test suite"
	@echo "  make reproducible  build twice, require identical merkle roots"
	@echo "  make doctor        report environment readiness"
	@echo "  make catalog       show what can be paid for, in SEI"
	@echo "  make validate      validate \$$INTENT"
	@echo "  make design        resolve \$$INTENT into a build plan"
	@echo "  make build         generate, price, sign, store"
	@echo "  make quote         price a build and issue a payment request"
	@echo "  make verify        verify \$$OUT against its signed manifest"
	@echo "  make iceberg       inspect the object store"
	@echo "  make serve         run the REST API on :8787"
	@echo "  make clean         remove .forge state"
	@echo
	@echo "  INTENT=$(INTENT)"
	@echo "  network=$(FORGE_SEI_NETWORK) (mainnet requires FORGE_ALLOW_MAINNET=1)"

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

check: test
	$(PYTHON) -m forge validate $(INTENT)

doctor:
	$(PYTHON) -m forge doctor

catalog:
	$(PYTHON) -m forge catalog

validate:
	$(PYTHON) -m forge validate $(INTENT)

design:
	$(PYTHON) -m forge design $(INTENT)

build:
	$(PYTHON) -m forge build $(INTENT) --out $(OUT)

quote:
	$(PYTHON) -m forge quote $(INTENT)

verify:
	$(PYTHON) -m forge verify $(OUT)

iceberg:
	$(PYTHON) -m forge iceberg

serve:
	$(PYTHON) -m forge serve --host 0.0.0.0 --port 8787

# The property everything else rests on: same intent, same bytes.
reproducible:
	@rm -rf .forge/repro-a .forge/repro-b
	@mkdir -p .forge
	@$(PYTHON) -m forge build $(INTENT) --workdir .forge/repro-a --out .forge/repro-a/out --no-sign --json \
		| $(PYTHON) -c 'import json,sys; print(json.load(sys.stdin)["merkle_root"])' > .forge/root-a
	@$(PYTHON) -m forge build $(INTENT) --workdir .forge/repro-b --out .forge/repro-b/out --no-sign --json \
		| $(PYTHON) -c 'import json,sys; print(json.load(sys.stdin)["merkle_root"])' > .forge/root-b
	@diff -r .forge/repro-a/out .forge/repro-b/out
	@diff .forge/root-a .forge/root-b \
		&& echo "reproducible: $$(cat .forge/root-a)" \
		|| (echo "NOT REPRODUCIBLE" && exit 1)

clean:
	rm -rf .forge
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
