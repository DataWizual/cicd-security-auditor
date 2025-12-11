#!/bin/bash

# CI/CD Security Auditor - Run Script
# Simplified wrapper for running security audits

set -e

print_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                 CI/CD Security Auditor                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
}

print_usage() {
    echo "Usage: $0 [OPTIONS] [TARGET]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -m, --mode MODE     Audit mode (full, quick, secrets, deps, cicd, git)"
    echo "  -o, --output DIR    Output directory for reports"
    echo "  -c, --config FILE   Configuration file"
    echo "  --skip-tool-check   Skip tool availability check"
    echo "  --api               Use API mode (requires audit_api.py)"
    echo ""
    echo "Target can be:"
    echo "  • Local directory path"
    echo "  • GitHub URL (https://github.com/user/repo)"
    echo "  • Git repository URL"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/repo"
    echo "  $0 https://github.com/user/repo"
    echo "  $0 . --mode quick"
    echo "  $0 ../project --output ./my-reports"
}

check_requirements() {
    echo "🔧 Checking requirements..."
    
    # Check Python
    if command -v python3 &>/dev/null; then
        echo "  ✓ Python 3"
    else
        echo "  ✗ Python 3 not found"
        exit 1
    fi
    
    # Check main script
    if [ -f "src/main.py" ]; then
        echo "  ✓ main.py"
    else
        echo "  ✗ main.py not found in src/ directory"
        exit 1
    fi
    
    # Check git
    if command -v git &>/dev/null; then
        echo "  ✓ git"
    else
        echo "  ⚠ git not found (required for GitHub URLs)"
    fi
}

run_local_audit() {
    local target="$1"
    local mode="$2"
    local output="$3"
    local config="$4"
    local skip_check="$5"
    
    echo "🔍 Running local audit..."
    echo "Target: $target"
    echo "Mode: $mode"
    
    local cmd="python3 src/main.py \"$target\" --mode $mode"
    
    if [ -n "$output" ]; then
        cmd="$cmd --output \"$output\""
    fi
    
    if [ -n "$config" ] && [ -f "$config" ]; then
        cmd="$cmd --config \"$config\""
    fi
    
    if [ "$skip_check" = "true" ]; then
        cmd="$cmd --skip-tool-check"
    fi
    
    echo "Running: $cmd"
    echo ""
    
    eval "$cmd"
}

run_github_audit() {
    local url="$1"
    local mode="$2"
    local output="$3"
    
    echo "🌐 Running GitHub audit..."
    echo "URL: $url"
    echo "Mode: $mode"
    
    if [ ! -f "src/audit_github.py" ]; then
        echo "✗ audit_github.py not found in src/"
        echo "Please run from the project directory or install the script."
        exit 1
    fi
    
    local cmd="python3 src/audit_github.py \"$url\""
    
    if [ "$mode" != "full" ]; then
        cmd="$cmd $mode"
    fi
    
    echo "Running: $cmd"
    echo ""
    
    eval "$cmd"
}

run_api_audit() {
    local target="$1"
    local mode="$2"
    
    echo "📡 Running API audit..."
    
    if [ ! -f "audit_api.py" ]; then
        echo "✗ audit_api.py not found in project root"
        exit 1
    fi
    
    # Check if API is running
    if curl -s http://localhost:5000/health > /dev/null 2>&1; then
        echo "  ✓ API is running"
    else
        echo "⚠ Starting API server..."
        python3 audit_api.py > /dev/null 2>&1 &
        API_PID=$!
        sleep 3
    fi
    
    # Make API request
    echo "Sending audit request for: $target"
    
    response=$(curl -s -X POST http://localhost:5000/audit \
        -H "Content-Type: application/json" \
        -d "{\"repo_url\": \"$target\", \"mode\": \"$mode\"}" 2>/dev/null || echo '{"error":"connection failed"}')
    
    # Extract job_id safely
    job_id=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('job_id', 'ERROR'))
except:
    print('ERROR')
")
    
    if [ "$job_id" = "ERROR" ]; then
        echo "❌ Failed to create audit job"
        echo "Response: $response"
        exit 1
    fi
    
    echo "✅ Audit job created: $job_id"
    echo ""
    echo "Check status:"
    echo "  curl http://localhost:5000/status/$job_id"
    echo ""
    echo "Or view in browser:"
    echo "  http://localhost:5000/status/$job_id"
    
    # Wait for completion
    echo "⏳ Waiting for audit to complete..."
    
    for i in {1..30}; do  # Max 30 attempts (150 seconds)
        status=$(curl -s "http://localhost:5000/status/$job_id" 2>/dev/null | python3 -c "
import sys, json
try:
    data = sys.stdin.read()
    if data:
        print(json.loads(data).get('status', 'unknown'))
    else:
        print('unknown')
except:
    print('unknown')
" 2>/dev/null || echo "unknown")
        
        case "$status" in
            "completed")
                echo "✅ Audit completed!"
                break
                ;;
            "failed")
                echo "❌ Audit failed"
                break
                ;;
            "unknown")
                if [ $i -eq 30 ]; then
                    echo "❌ Timeout waiting for audit"
                fi
                ;;
        esac
        
        [ "$status" = "completed" ] || [ "$status" = "failed" ] && break
        
        echo -n "."
        sleep 5
    done
    
    # Kill API server if we started it
    if [ -n "$API_PID" ]; then
        kill "$API_PID" 2>/dev/null || true
    fi
}

# Main script
print_header

# Default values
MODE="full"
OUTPUT=""
CONFIG=""
SKIP_CHECK="false"
USE_API="false"
TARGET=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG="$2"
            shift 2
            ;;
        --skip-tool-check)
            SKIP_CHECK="true"
            shift
            ;;
        --api)
            USE_API="true"
            shift
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

# Validate mode
VALID_MODES=("full" "quick" "secrets" "deps" "cicd" "git")
if [[ ! " ${VALID_MODES[@]} " =~ " ${MODE} " ]]; then
    echo "❌ Invalid mode: $MODE"
    echo "Valid modes: ${VALID_MODES[*]}"
    exit 1
fi

# If no target provided, use current directory
if [ -z "$TARGET" ]; then
    TARGET="."
    echo "⚠ No target specified, using current directory"
fi

# Check requirements
check_requirements

# Determine audit type and run
if [ "$USE_API" = "true" ]; then
    run_api_audit "$TARGET" "$MODE"
elif [[ "$TARGET" == http* ]] || [[ "$TARGET" == git* ]]; then
    # GitHub or Git URL
    run_github_audit "$TARGET" "$MODE" "$OUTPUT"
else
    # Local path
    if [ ! -e "$TARGET" ]; then
        echo "❌ Target not found: $TARGET"
        exit 1
    fi
    run_local_audit "$TARGET" "$MODE" "$OUTPUT" "$CONFIG" "$SKIP_CHECK"
fi

echo ""
echo "✨ Audit process completed!"