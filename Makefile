# Master Makefile for BOF Development Repository
#
# Builds all Beacon Object Files (BOFs) in the repository
#
# Usage:
#   make          - Compile all BOFs (x64 and x86)
#   make test     - Compile test executables for all BOFs
#   make clean    - Remove all compiled artifacts
#   make list     - List all available BOFs

# BOF directories (production-ready)
BOFS := src/adduser-domaingroup \
        src/adduser-localgroup \
        src/bkread \
        src/credguard-check \
        src/checkaccess \
        src/curl \
        src/decrypt-credmanager \
        src/dpapi-unprotect \
        src/dsreg-status \
        src/edge-passdump \
        src/enum-credmanager \
        src/enum-creds \
        src/enum-logon-events \
        src/enum-registry \
        src/enum-stored-accounts \
        src/enum-user-right \
        src/enumshares \
        src/listpipes \
        src/lsfiles \
        src/nslookup-file \
        src/removeuser-domaingroup \
        src/removeuser-localgroup \
        src/sccm-disk \
        src/sccm-local-recon \
        src/sccm-wmi \
        src/tcpscan

# Linked BOF-PE projects (x64 PE output, not COFF objects)
BOF_PES := src/fake-windows-popup-async

# Color output
COLOR_RESET := \033[0m
COLOR_BOLD := \033[1m
COLOR_GREEN := \033[32m
COLOR_BLUE := \033[34m
COLOR_YELLOW := \033[33m
COLOR_RED := \033[31m

# Default target: build all BOFs
all:
	@echo "$(COLOR_BOLD)$(COLOR_BLUE)================================================$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)$(COLOR_BLUE)  Building All BOFs$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)$(COLOR_BLUE)================================================$(COLOR_RESET)"
	@echo ""
	@for bof in $(BOFS); do \
		echo "$(COLOR_BOLD)$(COLOR_GREEN)[*] Building $$bof...$(COLOR_RESET)"; \
		$(MAKE) -C $$bof all || exit 1; \
		echo ""; \
	done
	@for bof in $(BOF_PES); do \
		echo "$(COLOR_BOLD)$(COLOR_GREEN)[*] Building BOF-PE $$bof...$(COLOR_RESET)"; \
		$(MAKE) -C $$bof all || exit 1; \
		echo ""; \
	done
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)================================================$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)  All BOFs compiled successfully!$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)================================================$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Compiled BOF files:$(COLOR_RESET)"
	@find src -name "*.x64.o" -o -name "*.x86.o" | sort
	@find src -path "*/build-mingw/*.exe" -type f | sort

# Test target: build test executables for all BOFs
test:
	@echo "$(COLOR_BOLD)$(COLOR_BLUE)================================================$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)$(COLOR_BLUE)  Building Test Executables$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)$(COLOR_BLUE)================================================$(COLOR_RESET)"
	@echo ""
	@for bof in $(BOFS); do \
		echo "$(COLOR_BOLD)$(COLOR_YELLOW)[*] Building test executable for $$bof...$(COLOR_RESET)"; \
		$(MAKE) -C $$bof test || exit 1; \
		echo ""; \
	done
	@for bof in $(BOF_PES); do \
		echo "$(COLOR_BOLD)$(COLOR_YELLOW)[*] Running BOF-PE tests for $$bof...$(COLOR_RESET)"; \
		$(MAKE) -C $$bof test || exit 1; \
		echo ""; \
	done
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)================================================$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)  All test executables compiled!$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)================================================$(COLOR_RESET)"

# Clean target: remove all compiled artifacts
clean:
	@echo "$(COLOR_BOLD)$(COLOR_YELLOW)Cleaning all BOF artifacts...$(COLOR_RESET)"
	@for bof in $(BOFS) $(BOF_PES); do \
		echo "  - Cleaning $$bof"; \
		$(MAKE) -C $$bof clean 2>/dev/null || true; \
	done
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)All artifacts cleaned.$(COLOR_RESET)"

# List all available BOFs
list:
	@echo "$(COLOR_BOLD)Available BOFs:$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)Production Ready:$(COLOR_RESET)"
	@for bof in $(BOFS); do \
		echo "  $(COLOR_GREEN)✓$(COLOR_RESET) $$(basename $$bof)"; \
	done
	@echo ""
	@echo "$(COLOR_BOLD)$(COLOR_GREEN)BOF-PE:$(COLOR_RESET)"
	@for bof in $(BOF_PES); do \
		echo "  $(COLOR_GREEN)✓$(COLOR_RESET) $$(basename $$bof) (x64)"; \
	done
	@echo ""
	@echo "$(COLOR_BOLD)Total: $(words $(BOFS)) BOFs, $(words $(BOF_PES)) BOF-PEs$(COLOR_RESET)"

# Build specific BOF
%:
	@if echo "$(BOFS) $(BOF_PES)" | grep -qw "src/$@"; then \
		echo "$(COLOR_BOLD)$(COLOR_GREEN)[*] Building $@...$(COLOR_RESET)"; \
		$(MAKE) -C src/$@ all; \
	else \
		echo "$(COLOR_BOLD)$(COLOR_YELLOW)Unknown BOF: $@$(COLOR_RESET)"; \
		echo "Run 'make list' to see available BOFs"; \
		exit 1; \
	fi

# Help target
help:
	@echo "$(COLOR_BOLD)BOF Development Repository - Master Makefile$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Usage:$(COLOR_RESET)"
	@echo "  make          - Compile all production-ready BOFs (x64 and x86 object files)"
	@echo "  make test     - Compile test executables for all BOFs"
	@echo "  make clean    - Remove all compiled artifacts"
	@echo "  make list     - List all available BOFs"
	@echo "  make <bof>    - Build specific BOF (e.g., make enum-logon-events)"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "$(COLOR_BOLD)BOFs:$(COLOR_RESET)"
	@for bof in $(BOFS); do \
		echo "  - $$(basename $$bof)"; \
	done
	@echo ""
	@echo "$(COLOR_BOLD)BOF-PEs:$(COLOR_RESET)"
	@for bof in $(BOF_PES); do \
		echo "  - $$(basename $$bof)"; \
	done

.PHONY: all test clean list help
