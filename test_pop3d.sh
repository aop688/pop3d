#!/bin/bash
#
# Test script for pop3d - Production POP3 Server
#

# Don't exit on error - we want to run all tests
set +e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
TEST_DIR="$(pwd)/test_env"
TEST_PORT=9110
TEST_SSL_PORT=9995
PIDFILE="$TEST_DIR/pop3d.pid"
LOGFILE="$TEST_DIR/pop3d.log"

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

cleanup() {
    if [ -f "$PIDFILE" ]; then
        kill $(cat "$PIDFILE" 2>/dev/null) 2>/dev/null
        wait $(cat "$PIDFILE" 2>/dev/null) 2>/dev/null
        rm -f "$PIDFILE"
    fi
    rm -rf "$TEST_DIR"
}

setup() {
    log_info "Setting up test environment..."
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR/maildir"/{cur,new,tmp}
    mkdir -p "$TEST_DIR/certs"
    
    # Create test emails
    echo -e "From: test@example.com\nSubject: Test 1\n\nMessage 1" > "$TEST_DIR/maildir/new/msg1"
    echo -e "From: test@example.com\nSubject: Test 2\n\nMessage 2" > "$TEST_DIR/maildir/new/msg2"
    
    # Create config
    cat > "$TEST_DIR/pop3d.conf" << EOF
port = $TEST_PORT
ssl_port = $TEST_SSL_PORT
allow_plaintext = 1
max_connections = 10
log_auth = 1
cert_file = $TEST_DIR/certs/test.crt
key_file = $TEST_DIR/certs/test.key
maildir_base = $TEST_DIR/maildir
EOF

    # Generate test certificate
    openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "$TEST_DIR/certs/test.key" \
        -out "$TEST_DIR/certs/test.crt" \
        -subj "/CN=localhost" 2>/dev/null
    
    log_info "Test environment ready"
}

start_server() {
    log_info "Starting server on port $TEST_PORT..."
    
    ./pop3d -c "$TEST_DIR/pop3d.conf" -d > "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    
    # Wait for server to start
    for i in {1..15}; do
        if nc -z localhost $TEST_PORT 2>/dev/null; then
            log_info "Server is listening"
            return 0
        fi
        sleep 0.3
    done
    
    log_error "Server failed to start"
    cat "$LOGFILE" 2>/dev/null
    return 1
}

pop3_cmd() {
    printf '%s\r\n' "$1" | timeout 3 nc localhost $TEST_PORT 2>/dev/null
}

# Tests
test_help() {
    log_info "Test: CLI help"
    local out=$(./pop3d -h 2>&1)
    if echo "$out" | grep -q "Usage"; then
        pass "Help option works"
    else
        fail "Help option failed"
    fi
}

test_greeting() {
    log_info "Test: Server greeting"
    local resp=$(pop3_cmd "QUIT" | head -1)
    if echo "$resp" | grep -q "+OK"; then
        pass "Server responds with +OK"
    else
        fail "No +OK greeting: $resp"
    fi
}

test_capa() {
    log_info "Test: CAPA command"
    local resp=$(pop3_cmd "CAPA")
    if echo "$resp" | grep -q "USER"; then
        pass "CAPA works"
    else
        fail "CAPA failed"
    fi
}

test_noop() {
    log_info "Test: NOOP command"
    local resp=$(pop3_cmd "NOOP" | head -1)
    if echo "$resp" | grep -q "+OK"; then
        pass "NOOP works"
    else
        fail "NOOP failed"
    fi
}

test_auth_required() {
    log_info "Test: Auth required for STAT"
    local resp=$(pop3_cmd "STAT")
    if echo "$resp" | grep -q -- "-ERR"; then
        pass "STAT requires auth"
    else
        fail "STAT should require auth (got: $resp)"
    fi
}

test_invalid() {
    log_info "Test: Invalid command"
    local resp=$(pop3_cmd "INVALID")
    if echo "$resp" | grep -q -- "-ERR"; then
        pass "Invalid cmd returns -ERR"
    else
        fail "Invalid cmd handling failed (got: $resp)"
    fi
}

test_concurrent() {
    log_info "Test: Multiple sequential connections"
    local ok=0
    
    # Test multiple sequential connections
    for i in 1 2 3; do
        local resp=$(pop3_cmd "QUIT" | head -1)
        if echo "$resp" | grep -q "+OK"; then
            ok=$((ok + 1))
        fi
        sleep 0.1
    done
    
    if [ $ok -eq 3 ]; then
        pass "Sequential: 3/3 OK"
    else
        fail "Sequential: only $ok/3 OK"
    fi
}

test_maildir() {
    log_info "Test: Maildir structure"
    local count=$(ls -1 "$TEST_DIR/maildir/new" 2>/dev/null | wc -l)
    if [ "$count" -eq 2 ]; then
        pass "Maildir has 2 messages"
    else
        fail "Expected 2 messages, got $count"
    fi
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "           TEST SUMMARY"
    echo "=========================================="
    echo "Tests run:    $TESTS_RUN"
    echo -e "${GREEN}Passed:       $TESTS_PASSED${NC}"
    [ $TESTS_FAILED -gt 0 ] && echo -e "${RED}Failed:       $TESTS_FAILED${NC}" || echo "Failed:       $TESTS_FAILED"
    echo "=========================================="
    [ $TESTS_FAILED -eq 0 ] && echo -e "${GREEN}All tests passed!${NC}" || echo -e "${RED}Some tests failed!${NC}"
    return $TESTS_FAILED
}

main() {
    echo "=========================================="
    echo "       POP3D Test Suite"
    echo "=========================================="
    
    if [ ! -x "./pop3d" ]; then
        log_error "pop3d binary not found. Run 'make' first."
        exit 1
    fi
    
    if ! command -v nc >/dev/null 2>&1; then
        log_error "netcat (nc) required"
        exit 1
    fi
    
    trap cleanup EXIT
    
    setup
    test_help
    test_maildir
    
    if ! start_server; then
        exit 1
    fi
    
    sleep 1
    
    test_greeting
    test_capa
    test_noop
    test_auth_required
    test_invalid
    test_concurrent
    
    print_summary
    exit $TESTS_FAILED
}

main
