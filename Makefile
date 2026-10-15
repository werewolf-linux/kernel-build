PYTHON ?= python3
ARCH ?= $(shell uname -m)
MELANGE ?= $(if $(wildcard build/tools/melange),$(abspath build/tools/melange),melange)
export MELANGE
LOCK = build/inputs/kernel.lock.json
VERSION = $(shell $(PYTHON) -c 'import json; print(json.load(open("$(LOCK)"))["version"])')

.PHONY: refresh verify config check build
refresh:
	$(PYTHON) scripts/refresh.py

$(LOCK):
	$(PYTHON) scripts/refresh.py

verify: $(LOCK)
	$(PYTHON) scripts/verify.py

# Needs clang 22 or later, ld.lld and GNU make 4 (gmake on macOS).
config: $(LOCK)
	$(PYTHON) scripts/refresh.py --unpack
	for arch in x86_64 aarch64; do \
		$(PYTHON) scripts/config.py generate --arch $$arch --source build/source/linux-$(VERSION) \
			--make $(MAKE) || exit 1; \
	done

check:
	$(PYTHON) scripts/config.py check --arch x86_64
	$(PYTHON) scripts/config.py check --arch aarch64
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

build: verify
	$(PYTHON) scripts/signing-key.py
	$(PYTHON) scripts/build.py --arch $(ARCH)
