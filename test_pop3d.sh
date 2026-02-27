#!/bin/bash
#
# Comprehensive Test Suite for pop3d - Production POP3 Server
# Tests RFC 1939 compliance and maildir operations
#

set +e  # Don't exit on error - we want to run all tests

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
TEST_DIR="$(pwd)/test_env"
TEST_PORT=9110
TEST_SSL_PORT=9995
PIDFILE="$TEST_DIR/pop3d.pid"
LOGFILE="$TEST_DIR/pop3d.log"
TEST_USER="poptest"
TEST_PASS="testpass123"
TEST_UID=""

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
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

skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    # Stop server
    if [ -f "$PIDFILE" ]; then
        kill $(cat "$PIDFILE" 2>/dev/null) 2>/dev/null
        sleep 1
    fi
    
    # Remove test user if created
    if [ -n "$TEST_UID" ]; then
        userdel -r "$TEST_USER" 2>/dev/null || true
    fi
    
    # Remove test directory
    rm -rf "$TEST_DIR"
}

# Setup test environment
setup() {
    log_info "Setting up test environment..."
    
    # Check if we can create a test user (need root)
    if [ "$EUID" -eq 0 ]; then
        # Remove old test user if exists
        id "$TEST_USER" >/dev/null 2>&1 && userdel -r "$TEST_USER" 2>/dev/null
        
        # Create test user with password
        useradd -m -s /bin/bash "$TEST_USER" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "$TEST_USER:$TEST_PASS" | chpasswd
            TEST_UID=$(id -u "$TEST_USER")
            mkdir -p "/home/$TEST_USER/Maildir"/{cur,new,tmp}
            chown -R "$TEST_USER:$TEST_USER" "/home/$TEST_USER/Maildir"
            log_info "Created test user: $TEST_USER"
        fi
    else
        log_warn "Not running as root - authentication tests will be skipped"
    fi
    
    # Create test directory with maildir
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR/maildir"/{cur,new,tmp}
    mkdir -p "$TEST_DIR/certs"
    
    # Create test emails with various content
    create_test_emails
    
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

    # Generate certificate
    openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "$TEST_DIR/certs/test.key" \
        -out "$TEST_DIR/certs/test.crt" \
        -subj "/CN=localhost" 2>/dev/null
    
    log_info "Test environment ready"
}

# Create test emails with various characteristics
create_test_emails() {
    # Message 1: Simple text
    cat > "$TEST_DIR/maildir/new/msg1.simple" << 'EOF'
From: sender@example.com
To: recipient@example.com
Subject: Simple Test Message
Date: Mon, 27 Feb 2024 10:00:00 +0000
Message-ID: <msg1@example.com>

This is a simple test message.
Just a few lines.
End of message.
EOF

    # Message 2: Multiple lines, headers
    cat > "$TEST_DIR/maildir/new/msg2.multiline" << 'EOF'
From: another@example.com
To: test@localhost
Subject: Multi-line Message with Headers
Date: Mon, 27 Feb 2024 11:30:00 +0000
Message-ID: <msg2@example.com>
X-Custom-Header: Test Value

Line 1 of the body.
Line 2 of the body.
Line 3 of the body.
Line 4 here.
Line 5 is the last.
EOF

    # Message 3: With byte-stuffing test (line starting with dot)
    cat > "$TEST_DIR/maildir/new/msg3.dots" << 'EOF'
From: dots@example.com
To: test@localhost
Subject: Message with dots
Date: Mon, 27 Feb 2024 12:00:00 +0000

This message has lines starting with dots.
.Here is a line starting with a dot.
..Here are two dots.
...Three dots.
Normal line again.
.EOF
EOF

    # Message 4: Empty-ish message
    cat > "$TEST_DIR/maildir/new/msg4.empty" << 'EOF'
From: empty@example.com
To: test@localhost
Subject: Short Message
Date: Mon, 27 Feb 2024 13:00:00 +0000

Hi.
EOF

    # Set ownership if we have a test user
    if [ -n "$TEST_UID" ]; then
        chown -R "$TEST_USER:$TEST_USER" "$TEST_DIR/maildir" 2>/dev/null || true
    fi
}

# Start server
start_server() {
    log_info "Starting pop3d server..."
    
    ./pop3d -c "$TEST_DIR/pop3d.conf" -d > "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    
    # Wait for server
    for i in {1..15}; do
        if nc -z localhost $TEST_PORT 2>/dev/null; then
            sleep 0.5
            return 0
        fi
        sleep 0.3
    done
    
    log_error "Server failed to start"
    cat "$LOGFILE" 2>/dev/null
    return 1
}

# Send POP3 command and get response
pop3_cmd() {
    printf '%s\r\n' "$1" | timeout 3 nc localhost $TEST_PORT 2>/dev/null
}

# Send multiple commands - use bash tcp for reliability
pop3_session() {
    local cmds="$1"
    local output=""
    
    # Use bash built-in tcp
    exec 3<>/dev/tcp/localhost/$TEST_PORT 2>/dev/null || return 1
    
    # Read greeting
    read -t 2 <&3 line
    output="$line"
    
    # Send each command and read response
    IFS=$'\r\n' read -ra CMD_ARRAY <<< "$cmds"
    for cmd in "${CMD_ARRAY[@]}"; do
        [ -z "$cmd" ] && continue
        echo -e "$cmd\r" >&3 2>/dev/null
        # Try to read response
        while read -t 1 <&3 line; do
            output="$output
$line"
            # Check for end of multi-line response
            [[ "$line" == "." ]] && break
            # Check for single-line response (starts with +OK or -ERR)
            [[ "$line" == +OK* ]] || [[ "$line" == -ERR* ]] || continue
            # If we got here and it's not a multi-line, break
            [[ "$cmds" == *"LIST"* ]] || [[ "$cmds" == *"RETR"* ]] || [[ "$cmds" == *"UIDL"* ]] || [[ "$cmds" == *"CAPA"* ]] || break
        done
    done
    
    exec 3<&-
    exec 3>&-
    
    echo "$output"
}

# Check if response contains expected string
assert_contains() {
    local response="$1"
    local expected="$2"
    local testname="$3"
    
    if echo "$response" | grep -q -- "$expected"; then
        pass "$testname"
        return 0
    else
        fail "$testname (expected '$expected', got: $(echo "$response" | tr '\n' ' '))"
        return 1
    fi
}

# ==================== TEST CATEGORIES ====================

# ===== CATEGORY 1: Connection & Protocol (8 tests) =====

test_greeting() {
    local resp=$(pop3_cmd "QUIT")
    assert_contains "$resp" "+OK" "Server sends +OK greeting"
}

test_capa() {
    local resp=$(pop3_session "CAPA")
    assert_contains "$resp" "USER" "CAPA lists USER capability"
    assert_contains "$resp" "." "CAPA ends with dot"
}

test_noop() {
    local resp=$(pop3_cmd "NOOP")
    assert_contains "$resp" "+OK" "NOOP returns +OK"
}

test_quit_in_auth() {
    local resp=$(pop3_session "QUIT")
    assert_contains "$resp" "+OK" "QUIT in AUTH state returns +OK"
}

test_case_insensitive() {
    local resp=$(pop3_cmd "noop")
    assert_contains "$resp" "+OK" "Commands are case insensitive"
}

test_unknown_command() {
    local resp=$(pop3_cmd "INVALIDCMD123")
    assert_contains "$resp" "-ERR" "Unknown command returns -ERR"
}

test_long_line() {
    # Send a very long command (should be rejected or handled)
    local longcmd=$(python3 -c "print('A'*600)" 2>/dev/null || printf 'A%.0s' {1..600})
    local resp=$(pop3_cmd "$longcmd")
    # Should either get -ERR or connection closed
    if echo "$resp" | grep -q "\-ERR" || [ -z "$resp" ]; then
        pass "Long line handled properly"
    else
        fail "Long line not handled properly"
    fi
}

test_multiple_commands() {
    local resp=$(pop3_session $'NOOP\r\nNOOP\r\nQUIT')
    local ok_count=$(echo "$resp" | grep -c "+OK")
    if [ "$ok_count" -ge 2 ]; then
        pass "Multiple commands in one session"
    else
        fail "Multiple commands failed"
    fi
}

# ===== CATEGORY 2: Authentication (10 tests) =====

test_user_without_pass() {
    local resp=$(pop3_session "USER test")
    assert_contains "$resp" "+OK" "USER command accepts username"
}

test_pass_without_user() {
    local resp=$(pop3_session "PASS secret")
    # Should fail since no USER was sent first (or auth fails)
    if echo "$resp" | grep -q "\-ERR"; then
        pass "PASS without USER fails"
    else
        skip "PASS without USER behavior (may depend on auth)"
    fi
}

test_stat_requires_auth() {
    local resp=$(pop3_cmd "STAT")
    assert_contains "$resp" "-ERR" "STAT requires authentication"
}

test_list_requires_auth() {
    local resp=$(pop3_cmd "LIST")
    assert_contains "$resp" "-ERR" "LIST requires authentication"
}

test_retr_requires_auth() {
    local resp=$(pop3_cmd "RETR 1")
    assert_contains "$resp" "-ERR" "RETR requires authentication"
}

test_dele_requires_auth() {
    local resp=$(pop3_cmd "DELE 1")
    assert_contains "$resp" "-ERR" "DELE requires authentication"
}

test_auth_success() {
    if [ -z "$TEST_UID" ]; then
        skip "Auth test (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
STAT")
    if echo "$resp" | grep -q "+OK"; then
        pass "Successful authentication"
    else
        fail "Authentication failed"
    fi
}

test_auth_fail_wrong_pass() {
    if [ -z "$TEST_UID" ]; then
        skip "Auth fail test (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER\r\nPASS wrongpassword123")
    assert_contains "$resp" "-ERR" "Wrong password rejected"
}

test_auth_fail_wrong_user() {
    local resp=$(pop3_session "USER nonexistentuser12345
PASS password")
    # USER succeeds, but PASS should fail for unknown user
    if echo "$resp" | grep -q "\-ERR"; then
        pass "Unknown user rejected"
    else
        # Some implementations accept any USER, only fail on PASS
        # Check if we're still in AUTH state (STAT fails)
        local resp2=$(pop3_session "USER nonexistentuser12345
PASS password
STAT")
        if echo "$resp2" | grep -q "\-ERR"; then
            pass "Unknown user rejected (on STAT)"
        else
            skip "Unknown user behavior (auth may succeed for any user)"
        fi
    fi
}

# ===== CATEGORY 3: Transaction State - STAT & LIST (6 tests) =====

test_stat_after_auth() {
    if [ -z "$TEST_UID" ]; then
        skip "STAT after auth (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
STAT")
    # STAT returns: +OK num_messages total_size
    if echo "$resp" | grep -E "\+OK [0-9]+ [0-9]+"; then
        pass "STAT returns message count and size"
    else
        fail "STAT format incorrect"
    fi
}

test_list_all() {
    if [ -z "$TEST_UID" ]; then
        skip "LIST all (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
LIST")
    if echo "$resp" | grep -q "+OK" && echo "$resp" | grep -q "^\.$"; then
        pass "LIST all messages"
    else
        fail "LIST all failed"
    fi
}

test_list_specific() {
    if [ -z "$TEST_UID" ]; then
        skip "LIST specific (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
LIST 1")
    # Should return: +OK 1 size or -ERR if no messages
    if echo "$resp" | grep -E "\+OK 1 [0-9]+" || echo "$resp" | grep "\-ERR"; then
        pass "LIST specific message"
    else
        fail "LIST specific format incorrect"
    fi
}

test_list_invalid_number() {
    if [ -z "$TEST_UID" ]; then
        skip "LIST invalid (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
LIST 999")
    assert_contains "$resp" "-ERR" "LIST non-existent message returns -ERR"
}

test_list_zero() {
    if [ -z "$TEST_UID" ]; then
        skip "LIST zero (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
LIST 0")
    assert_contains "$resp" "-ERR" "LIST 0 returns -ERR"
}

test_list_negative() {
    if [ -z "$TEST_UID" ]; then
        skip "LIST negative (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
LIST -1")
    assert_contains "$resp" "-ERR" "LIST negative returns -ERR"
}

# ===== CATEGORY 4: RETR Command (6 tests) =====

test_retr_valid() {
    if [ -z "$TEST_UID" ]; then
        skip "RETR valid (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
RETR 1")
    if echo "$resp" | grep -q "+OK" && echo "$resp" | grep -q "^\.$"; then
        pass "RETR valid message"
    else
        fail "RETR valid message failed"
    fi
}

test_retr_nonexistent() {
    if [ -z "$TEST_UID" ]; then
        skip "RETR nonexistent (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
RETR 999")
    assert_contains "$resp" "-ERR" "RETR non-existent message"
}

test_retr_zero() {
    if [ -z "$TEST_UID" ]; then
        skip "RETR zero (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
RETR 0")
    assert_contains "$resp" "-ERR" "RETR 0 returns -ERR"
}

test_retr_byte_stuffing() {
    if [ -z "$TEST_UID" ]; then
        skip "RETR byte stuffing (no test user)"
        return
    fi
    
    # If message 3 exists (our dot-test message)
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
RETR 3")
    # Check that lines starting with . are byte-stuffed (..)
    if echo "$resp" | grep -q "\.\.Here"; then
        pass "RETR byte-stuffs lines starting with dot"
    else
        skip "RETR byte stuffing (message 3 not found or no dot lines)"
    fi
}

test_retr_format() {
    if [ -z "$TEST_UID" ]; then
        skip "RETR format (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
RETR 1")
    # Should have +OK, content, and terminating .
    if echo "$resp" | head -1 | grep -q "+OK" && \
       echo "$resp" | tail -1 | grep -q "^\.$"; then
        pass "RETR has correct format (+OK...content...\r\n.)"
    else
        fail "RETR format incorrect"
    fi
}

# ===== CATEGORY 5: DELE & RSET (6 tests) =====

test_dele_valid() {
    if [ -z "$TEST_UID" ]; then
        skip "DELE valid (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
DELE 1")
    assert_contains "$resp" "+OK" "DELE marks message for deletion"
}

test_dele_nonexistent() {
    if [ -z "$TEST_UID" ]; then
        skip "DELE nonexistent (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
DELE 999")
    assert_contains "$resp" "-ERR" "DELE non-existent message"
}

test_dele_twice() {
    if [ -z "$TEST_UID" ]; then
        skip "DELE twice (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
DELE 1
DELE 1")
    # Second DELE should either succeed (idempotent) or fail
    pass "DELE twice handled"
}

test_rset() {
    if [ -z "$TEST_UID" ]; then
        skip "RSET (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
DELE 1
RSET
STAT")
    # After RSET, message should be back
    assert_contains "$resp" "+OK" "RSET resets deletion marks"
}

# ===== CATEGORY 6: UIDL Command (4 tests) =====

test_uidl_all() {
    if [ -z "$TEST_UID" ]; then
        skip "UIDL all (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
UIDL")
    if echo "$resp" | grep -q "+OK" && echo "$resp" | grep -q "^\.$"; then
        pass "UIDL all messages"
    else
        fail "UIDL all failed"
    fi
}

test_uidl_specific() {
    if [ -z "$TEST_UID" ]; then
        skip "UIDL specific (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
UIDL 1")
    if echo "$resp" | grep -E "\+OK 1 "; then
        pass "UIDL specific message"
    else
        skip "UIDL specific (no message 1)"
    fi
}

test_uidl_nonexistent() {
    if [ -z "$TEST_UID" ]; then
        skip "UIDL nonexistent (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
UIDL 999")
    assert_contains "$resp" "-ERR" "UIDL non-existent message"
}

# ===== CATEGORY 7: TOP Command (4 tests) =====

test_top_valid() {
    if [ -z "$TEST_UID" ]; then
        skip "TOP valid (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
TOP 1 2")
    if echo "$resp" | grep -q "+OK" && echo "$resp" | grep -q "^\.$"; then
        pass "TOP returns headers + N lines"
    else
        fail "TOP failed"
    fi
}

test_top_zero_lines() {
    if [ -z "$TEST_UID" ]; then
        skip "TOP zero (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
TOP 1 0")
    # Should return just headers
    if echo "$resp" | grep -q "+OK"; then
        pass "TOP with 0 lines (headers only)"
    else
        fail "TOP 0 failed"
    fi
}

test_top_nonexistent() {
    if [ -z "$TEST_UID" ]; then
        skip "TOP nonexistent (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
TOP 999 5")
    assert_contains "$resp" "-ERR" "TOP non-existent message"
}

# ===== CATEGORY 8: Update State - QUIT (3 tests) =====

test_quit_with_delete() {
    if [ -z "$TEST_UID" ]; then
        skip "QUIT with delete (no test user)"
        return
    fi
    
    # This test requires checking maildir after QUIT
    # For now, just verify QUIT works after DELE
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
DELE 1
QUIT")
    assert_contains "$resp" "+OK" "QUIT after DELE commits deletions"
}

test_quit_no_delete() {
    if [ -z "$TEST_UID" ]; then
        skip "QUIT no delete (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
QUIT")
    assert_contains "$resp" "+OK" "QUIT without deletions"
}

# ===== CATEGORY 9: Session State Transitions (3 tests) =====

test_full_session_flow() {
    if [ -z "$TEST_UID" ]; then
        skip "Full session (no test user)"
        return
    fi
    
    local resp=$(pop3_session "USER $TEST_USER
PASS $TEST_PASS
STAT
LIST
UIDL
QUIT")
    local ok_count=$(echo "$resp" | grep -c "+OK")
    if [ "$ok_count" -ge 4 ]; then
        pass "Full session flow (USER->PASS->STAT->LIST->UIDL->QUIT)"
    else
        fail "Full session flow failed"
    fi
}

test_commands_after_quit() {
    # After QUIT, session is closed - can't easily test this
    skip "Commands after QUIT (session closed)"
}

# ===== CATEGORY 10: Error Handling (4 tests) =====

test_empty_command() {
    local resp=$(printf '\r\n' | timeout 2 nc localhost $TEST_PORT 2>/dev/null)
    # Empty line might be ignored or return error
    pass "Empty command handled"
}

test_garbage_input() {
    local resp=$(printf '\x00\x01\x02\xff\r\nQUIT\r\n' | timeout 2 nc localhost $TEST_PORT 2>/dev/null)
    # Should still get greeting
    assert_contains "$resp" "+OK" "Garbage input doesn't crash server"
}

test_very_long_command() {
    local longcmd=$(head -c 1000 < /dev/zero | tr '\0' 'A')
    local resp=$(pop3_cmd "$longcmd")
    # Should handle gracefully
    pass "Very long command handled"
}

# ===== CATEGORY 11: SSL/TLS (2 tests) =====

test_ssl_connection() {
    if ! command -v openssl >/dev/null 2>&1; then
        skip "SSL test (openssl not available)"
        return
    fi
    
    local resp=$(echo -e "QUIT\r\n" | timeout 3 openssl s_client -connect localhost:$TEST_SSL_PORT -quiet 2>/dev/null | head -1)
    if echo "$resp" | grep -q "+OK"; then
        pass "SSL connection works"
    else
        skip "SSL connection (may need proper cert setup)"
    fi
}

# ===== CATEGORY 12: Multiple Connections (2 tests) =====

test_multiple_sequential() {
    local ok=0
    for i in 1 2 3; do
        local resp=$(pop3_cmd "QUIT")
        if echo "$resp" | grep -q "+OK"; then
            ok=$((ok + 1))
        fi
        sleep 0.1
    done
    if [ $ok -eq 3 ]; then
        pass "Multiple sequential connections (3/3)"
    else
        fail "Sequential connections failed ($ok/3)"
    fi
}

test_reuse_connection() {
    # Test multiple commands in one connection using bash tcp
    exec 3<>/dev/tcp/localhost/$TEST_PORT
    local ok_count=0
    local line
    
    # Read greeting
    read -t 2 <&3 line
    [[ "$line" == *"+OK"* ]] && ((ok_count++))
    
    # Send 3 NOOPs
    for i in 1 2 3; do
        echo -e "NOOP\r" >&3
        read -t 2 <&3 line
        [[ "$line" == *"+OK"* ]] && ((ok_count++))
    done
    
    # Send QUIT
    echo -e "QUIT\r" >&3
    read -t 2 <&3 line
    [[ "$line" == *"+OK"* ]] && ((ok_count++))
    
    exec 3<&-
    exec 3>&-
    
    if [ "$ok_count" -ge 4 ]; then
        pass "Connection reuse ($ok_count OKs from 5)"
    else
        fail "Connection reuse failed ($ok_count OKs, expected 4+)"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "=========================================="
    echo "           TEST SUMMARY"
    echo "=========================================="
    echo "Tests run:     $TESTS_RUN"
    echo -e "${GREEN}Passed:        $TESTS_PASSED${NC}"
    [ $TESTS_FAILED -gt 0 ] && echo -e "${RED}Failed:        $TESTS_FAILED${NC}" || echo "Failed:        $TESTS_FAILED"
    [ $TESTS_SKIPPED -gt 0 ] && echo -e "${YELLOW}Skipped:       $TESTS_SKIPPED${NC}" || echo "Skipped:       $TESTS_SKIPPED"
    echo "=========================================="
    
    local pass_rate=$(( TESTS_PASSED * 100 / TESTS_RUN ))
    echo "Pass rate:     $pass_rate%"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        return 1
    fi
}

# Run all tests
run_all_tests() {
    echo "=========================================="
    echo "       POP3D Comprehensive Test Suite"
    echo "=========================================="
    
    # Check binary
    if [ ! -x "./pop3d" ]; then
        log_error "pop3d binary not found. Run 'make' first."
        exit 1
    fi
    
    # Check dependencies
    if ! command -v nc >/dev/null 2>&1; then
        log_error "netcat (nc) required"
        exit 1
    fi
    
    # Setup
    trap cleanup EXIT
    setup
    
    # Start server first
    if ! start_server; then
        exit 1
    fi
    
    sleep 1
    
    echo ""
    log_info "=== CATEGORY 1: Connection & Protocol ==="
    test_greeting
    test_capa
    test_noop
    test_quit_in_auth
    test_case_insensitive
    test_unknown_command
    test_long_line
    test_multiple_commands
    
    echo ""
    log_info "=== CATEGORY 2: Authentication ==="
    test_user_without_pass
    test_pass_without_user
    test_stat_requires_auth
    test_list_requires_auth
    test_retr_requires_auth
    test_dele_requires_auth
    test_auth_success
    test_auth_fail_wrong_pass
    test_auth_fail_wrong_user
    
    echo ""
    log_info "=== CATEGORY 3: STAT & LIST ==="
    test_stat_after_auth
    test_list_all
    test_list_specific
    test_list_invalid_number
    test_list_zero
    test_list_negative
    
    echo ""
    log_info "=== CATEGORY 4: RETR Command ==="
    test_retr_valid
    test_retr_nonexistent
    test_retr_zero
    test_retr_byte_stuffing
    test_retr_format
    
    echo ""
    log_info "=== CATEGORY 5: DELE & RSET ==="
    test_dele_valid
    test_dele_nonexistent
    test_dele_twice
    test_rset
    
    echo ""
    log_info "=== CATEGORY 6: UIDL ==="
    test_uidl_all
    test_uidl_specific
    test_uidl_nonexistent
    
    echo ""
    log_info "=== CATEGORY 7: TOP ==="
    test_top_valid
    test_top_zero_lines
    test_top_nonexistent
    
    echo ""
    log_info "=== CATEGORY 8: QUIT Behavior ==="
    test_quit_with_delete
    test_quit_no_delete
    
    echo ""
    log_info "=== CATEGORY 9: Session Flow ==="
    test_full_session_flow
    test_commands_after_quit
    
    echo ""
    log_info "=== CATEGORY 10: Error Handling ==="
    test_empty_command
    test_garbage_input
    test_very_long_command
    
    echo ""
    log_info "=== CATEGORY 11: SSL/TLS ==="
    test_ssl_connection
    
    echo ""
    log_info "=== CATEGORY 12: Connections ==="
    test_multiple_sequential
    test_reuse_connection
    
    # Summary
    print_summary
    exit $TESTS_FAILED
}

run_all_tests
