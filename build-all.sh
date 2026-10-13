#!/bin/bash
#
# Build All BOFs Script
#
# Builds all Beacon Object Files in the repository with enhanced
# error handling, progress tracking, and summary statistics.
#
# Usage:
#   ./build-all.sh              - Build all BOFs
#   ./build-all.sh test         - Build test executables
#   ./build-all.sh clean        - Clean all artifacts
#   ./build-all.sh <bof-name>   - Build specific BOF

set -e  # Exit on error

# Color codes
RESET='\033[0m'
BOLD='\033[1m'
GREEN='\033[32m'
BLUE='\033[34m'
YELLOW='\033[33m'
RED='\033[31m'

# BOF directories (production-ready) - keep in sync with root Makefile
BOFS=(
    "src/adduser-domaingroup"
    "src/adduser-localgroup"
    "src/bkread"
    "src/credguard-check"
    "src/checkaccess"
    "src/curl"
    "src/decrypt-credmanager"
    "src/dpapi-unprotect"
    "src/dsreg-status"
    "src/edge-passdump"
    "src/enum-credmanager"
    "src/enum-creds"
    "src/enum-logon-events"
    "src/enum-registry"
    "src/enum-stored-accounts"
    "src/enum-user-right"
    "src/enumshares"
    "src/listpipes"
    "src/lsfiles"
    "src/nslookup-file"
    "src/portscan"
    "src/removeuser-domaingroup"
    "src/removeuser-localgroup"
    "src/sccm-disk"
    "src/sccm-local-recon"
    "src/sccm-wmi"
)

# Linked x64 BOF-PE projects - keep in sync with root Makefile
BOF_PES=(
    "src/fake-windows-popup"
)

# Development/Issue BOFs
DEV_BOFS=(
)

# Statistics
SUCCESS_COUNT=0
FAILED_COUNT=0
TOTAL_COUNT=$((${#BOFS[@]} + ${#BOF_PES[@]}))

# Function: Print colored header
print_header() {
    echo -e "${BOLD}${BLUE}================================================${RESET}"
    echo -e "${BOLD}${BLUE}  $1${RESET}"
    echo -e "${BOLD}${BLUE}================================================${RESET}"
    echo ""
}

# Function: Print success message
print_success() {
    echo -e "${BOLD}${GREEN}✓${RESET} $1"
}

# Function: Print error message
print_error() {
    echo -e "${BOLD}${RED}✗${RESET} $1"
}

# Function: Print info message
print_info() {
    echo -e "${BOLD}${YELLOW}[*]${RESET} $1"
}

# Function: Print warning message
print_warning() {
    echo -e "${BOLD}${YELLOW}⚠${RESET} $1"
}

# Function: Build single BOF
build_bof() {
    local bof=$1
    local target=${2:-all}

    if [ ! -d "$bof" ]; then
        print_error "Directory not found: $bof"
        return 1
    fi

    if [ ! -f "$bof/Makefile" ]; then
        print_error "Makefile not found in $bof"
        return 1
    fi

    print_info "Building $bof..."

    if make -C "$bof" "$target" 2>&1; then
        print_success "$bof compiled successfully"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        return 0
    else
        print_error "$bof compilation failed"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        return 1
    fi
}

# Function: Build all production BOFs
build_all() {
    local target=${1:-all}
    local target_name="BOFs (Production Ready)"

    if [ "$target" = "test" ]; then
        target_name="test executables"
    fi

    TOTAL_COUNT=$((${#BOFS[@]} + ${#BOF_PES[@]}))
    print_header "Building All $target_name"

    for bof in "${BOFS[@]}"; do
        build_bof "$bof" "$target" || true  # Continue on error
        echo ""
    done

    for bof in "${BOF_PES[@]}"; do
        build_bof "$bof" "$target" || true
        echo ""
    done

    print_header "Build Summary"
    echo -e "Total BOFs:    ${BOLD}$TOTAL_COUNT${RESET}"
    echo -e "Successful:    ${BOLD}${GREEN}$SUCCESS_COUNT${RESET}"
    echo -e "Failed:        ${BOLD}${RED}$FAILED_COUNT${RESET}"
    echo ""

    if [ $FAILED_COUNT -eq 0 ]; then
        print_success "All BOFs compiled successfully!"
        echo ""
        echo -e "${BOLD}Compiled files:${RESET}"
        find src -name "*.x64.o" -o -name "*.x86.o" | sort
        find src -path "*/build-mingw/*.exe" -type f | sort
    else
        print_error "$FAILED_COUNT BOF(s) failed to compile"
        exit 1
    fi
}

# Function: Build all including development BOFs
build_all_dev() {
    local target=${1:-all}
    local target_name="BOFs (including dev)"

    if [ "$target" = "test" ]; then
        target_name="test executables (including dev)"
    fi

    TOTAL_COUNT=$((${#BOFS[@]} + ${#BOF_PES[@]} + ${#DEV_BOFS[@]}))
    print_header "Building All $target_name"

    # Build production BOFs
    for bof in "${BOFS[@]}"; do
        build_bof "$bof" "$target" || true  # Continue on error
        echo ""
    done
    for bof in "${BOF_PES[@]}"; do
        build_bof "$bof" "$target" || true
        echo ""
    done

    # Build development BOFs
    print_warning "Building development/issue BOFs..."
    echo ""
    for bof in "${DEV_BOFS[@]}"; do
        print_warning "Building $bof (has known issues)"
        build_bof "$bof" "$target" || true  # Continue on error
        echo ""
    done

    print_header "Build Summary"
    echo -e "Total BOFs:    ${BOLD}$TOTAL_COUNT${RESET}"
    echo -e "Successful:    ${BOLD}${GREEN}$SUCCESS_COUNT${RESET}"
    echo -e "Failed:        ${BOLD}${RED}$FAILED_COUNT${RESET}"
    echo ""

    if [ $FAILED_COUNT -eq 0 ]; then
        print_success "All BOFs compiled successfully!"
        echo ""
        echo -e "${BOLD}Compiled files:${RESET}"
        find src -name "*.x64.o" -o -name "*.x86.o" | sort
    else
        print_error "$FAILED_COUNT BOF(s) failed to compile"
        exit 1
    fi
}

# Function: Clean all BOFs
clean_all() {
    print_header "Cleaning All BOF Artifacts"

    for bof in "${BOFS[@]}" "${BOF_PES[@]}" "${DEV_BOFS[@]}"; do
        if [ -d "$bof" ]; then
            print_info "Cleaning $bof"
            make -C "$bof" clean 2>/dev/null || true
        fi
    done

    print_success "All artifacts cleaned"
}

# Function: List all BOFs
list_bofs() {
    print_header "Available BOFs"

    echo -e "${BOLD}${GREEN}Production Ready:${RESET}"
    for bof in "${BOFS[@]}"; do
        bof_name=$(basename "$bof")
        if [ -f "$bof/entry.c" ]; then
            # Extract description from entry.c if available
            desc=$(head -20 "$bof/entry.c" 2>/dev/null | grep -A1 "BOF" | grep "\*" | head -1 | sed 's/.*\* //' | sed 's/ *$//' || echo "")
            echo -e "  ${GREEN}✓${RESET} ${BOLD}$bof_name${RESET}"
            if [ -n "$desc" ]; then
                echo -e "    $desc"
            fi
        else
            echo -e "  ${YELLOW}?${RESET} $bof_name (entry.c not found)"
        fi
    done

    echo ""
    echo -e "${BOLD}${GREEN}BOF-PEs:${RESET}"
    for bof in "${BOF_PES[@]}"; do
        echo -e "  ${GREEN}✓${RESET} ${BOLD}$(basename "$bof")${RESET} (x64)"
    done

    echo ""
    echo -e "${BOLD}${YELLOW}Development/Issues (use './build-all.sh all-dev'):${RESET}"
    for bof in "${DEV_BOFS[@]}"; do
        bof_name=$(basename "$bof")
        echo -e "  ${YELLOW}⚠${RESET} ${BOLD}$bof_name${RESET} (has known issues - see docs/)"
    done

    echo ""
    echo -e "${BOLD}Total: ${#BOFS[@]} production BOFs, ${#BOF_PES[@]} BOF-PEs, ${#DEV_BOFS[@]} dev BOFs${RESET}"
}

# Function: Show help
show_help() {
    echo -e "${BOLD}BOF Development Repository - Build Script${RESET}"
    echo ""
    echo -e "${BOLD}Usage:${RESET}"
    echo "  $0              - Compile all production-ready BOFs (x64 and x86)"
    echo "  $0 all-dev      - Compile all BOFs including development/issue BOFs"
    echo "  $0 test         - Compile test executables for production BOFs"
    echo "  $0 clean        - Remove all compiled artifacts"
    echo "  $0 list         - List all available BOFs"
    echo "  $0 <bof-name>   - Build specific BOF"
    echo "  $0 help         - Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0                          # Build all production-ready BOFs"
    echo "  $0 all-dev                 # Build all including CredManBOF (has issues)"
    echo "  $0 logon-events            # Build only logon-events BOF"
    echo "  $0 test                    # Build test executables"
    echo ""
    echo -e "${BOLD}Production-Ready BOFs:${RESET}"
    for bof in "${BOFS[@]}"; do
        echo "  - $(basename $bof)"
    done
    echo ""
    echo -e "${BOLD}BOF-PEs:${RESET}"
    for bof in "${BOF_PES[@]}"; do
        echo "  - $(basename "$bof") (x64)"
    done
    echo ""
    echo -e "${BOLD}Development/Issue BOFs:${RESET}"
    for bof in "${DEV_BOFS[@]}"; do
        echo "  - $(basename $bof) (has known issues)"
    done
}

# Function: Check if BOF exists
bof_exists() {
    local bof=$1
    for b in "${BOFS[@]}" "${BOF_PES[@]}" "${DEV_BOFS[@]}"; do
        if [ "$(basename $b)" = "$bof" ] || [ "$b" = "src/$bof" ]; then
            return 0
        fi
    done
    return 1
}

# Main script logic
main() {
    # Change to script directory
    cd "$(dirname "$0")"

    # Parse command
    case "${1:-all}" in
        all)
            build_all "all"
            ;;
        all-dev)
            build_all_dev "all"
            ;;
        test)
            build_all "test"
            ;;
        clean)
            clean_all
            ;;
        list)
            list_bofs
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            # Check if it's a specific BOF name
            if bof_exists "$1"; then
                print_header "Building $1"
                if build_bof "src/$1" "all"; then
                    echo ""
                    print_success "$1 compiled successfully!"
                    echo ""
                    echo "Compiled files:"
                    find "src/$1" -maxdepth 2 -type f \( -name '*.o' -o -name '*.exe' \) -print
                else
                    exit 1
                fi
            else
                echo -e "${RED}Unknown command or BOF: $1${RESET}"
                echo ""
                show_help
                exit 1
            fi
            ;;
    esac
}

# Run main function
main "$@"
