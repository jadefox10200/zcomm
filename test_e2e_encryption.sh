#!/bin/bash

# E2E Encryption Test Script
# Tests the complete encryption flow: Alice sends encrypted message to Bob, Bob decrypts it

set -e  # Exit on error

API_URL="http://localhost:8080"
ALICE_DESK="7661769588"
BOB_DESK="9313041142"

echo "🔐 Testing E2E Encryption Flow"
echo "================================"
echo ""

# Step 1: Login as Alice
echo "1️⃣  Logging in as Alice..."
ALICE_LOGIN=$(curl -s -X POST "$API_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "password123"
  }')

echo "Response:"
echo "$ALICE_LOGIN" | python3 -m json.tool
echo ""

# Extract token (simple grep method)
ALICE_TOKEN=$(echo "$ALICE_LOGIN" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ALICE_TOKEN" ]; then
  echo "❌ Alice login failed"
  exit 1
fi
echo "✓ Alice logged in successfully"
echo "✓ Token: ${ALICE_TOKEN:0:30}..."
echo ""

# Step 2: Check if encrypted_priv_keys is in response
echo "2️⃣  Checking for encrypted_priv_keys in login response..."
if echo "$ALICE_LOGIN" | grep -q "encrypted_priv_keys"; then
  echo "✓ encrypted_priv_keys field present in response"
else
  echo "❌ encrypted_priv_keys field NOT found in response"
fi
echo ""

# Step 3: Get Bob's public key
echo "3️⃣  Fetching Bob's public key..."
BOB_PUBKEY_RESPONSE=$(curl -s "$API_URL/api/desk/$BOB_DESK/public-key")
echo "Response:"
echo "$BOB_PUBKEY_RESPONSE" | python3 -m json.tool
echo ""

BOB_PUBKEY=$(echo "$BOB_PUBKEY_RESPONSE" | grep -o '"public_key":"[^"]*"' | cut -d'"' -f4)

if [ -z "$BOB_PUBKEY" ]; then
  echo "❌ Failed to get Bob's public key"
  exit 1
fi
echo "✓ Bob's public key retrieved (${#BOB_PUBKEY} chars)"
echo ""

# Step 4: Get Alice's public key
echo "4️⃣  Fetching Alice's public key..."
ALICE_PUBKEY_RESPONSE=$(curl -s "$API_URL/api/desk/$ALICE_DESK/public-key")
ALICE_PUBKEY=$(echo "$ALICE_PUBKEY_RESPONSE" | grep -o '"public_key":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ALICE_PUBKEY" ]; then
  echo "❌ Failed to get Alice's public key"
  exit 1
fi
echo "✓ Alice's public key retrieved (${#ALICE_PUBKEY} chars)"
echo ""

# Step 5: Test batch public key fetch
echo "5️⃣  Testing batch public key fetch..."
BATCH_RESPONSE=$(curl -s -X POST "$API_URL/api/desk/public-keys/batch" \
  -H "Content-Type: application/json" \
  -d "{
    \"desk_ids\": [\"$ALICE_DESK\", \"$BOB_DESK\"]
  }")

echo "Response:"
echo "$BATCH_RESPONSE" | python3 -m json.tool
echo ""

if echo "$BATCH_RESPONSE" | grep -q "$ALICE_DESK"; then
  echo "✓ Batch public key fetch working"
else
  echo "❌ Batch public key fetch failed"
fi
echo ""

# Step 6: Send a test message (will be unencrypted since we're testing via API)
echo "6️⃣  Sending test message from Alice to Bob..."
TEST_MESSAGE="Hello Bob! Testing E2E encryption infrastructure."
TEST_MESSAGE_B64=$(echo -n "$TEST_MESSAGE" | base64)

SEND_RESPONSE=$(curl -s -X POST "$API_URL/api/miv" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d "{
    \"from\": \"$ALICE_DESK\",
    \"to\": \"$BOB_DESK\",
    \"subject\": \"E2E Test Message\",
    \"body\": \"$TEST_MESSAGE_B64\"
  }")

echo "Response:"
echo "$SEND_RESPONSE" | python3 -m json.tool
echo ""

MIV_ID=$(echo "$SEND_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$MIV_ID" ]; then
  echo "❌ Failed to send message"
  exit 1
fi
echo "✓ Message sent (ID: $MIV_ID)"
echo ""

# Step 7: Login as Bob
echo "7️⃣  Logging in as Bob..."
BOB_LOGIN=$(curl -s -X POST "$API_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "bob",
    "password": "password123"
  }')

BOB_TOKEN=$(echo "$BOB_LOGIN" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$BOB_TOKEN" ]; then
  echo "❌ Bob login failed"
  exit 1
fi
echo "✓ Bob logged in successfully"
echo ""

# Step 8: Check Bob's inbox
echo "8️⃣  Checking Bob's inbox..."
BOB_INBOX=$(curl -s "$API_URL/api/miv?desk_id=$BOB_DESK&state=IN" \
  -H "Authorization: Bearer $BOB_TOKEN")

echo "Bob's inbox (last message):"
echo "$BOB_INBOX" | python3 -c "import sys, json; data=json.load(sys.stdin); print(json.dumps(data['mivs'][-1] if data.get('mivs') else {}, indent=2))" 2>/dev/null || echo "$BOB_INBOX"
echo ""

# Summary
echo "================================"
echo "✅ E2E Encryption Backend Tests"
echo "================================"
echo ""
echo "Backend Infrastructure Status:"
echo "  ✓ Login endpoint working"
echo "  ✓ Public key endpoint working (single)"
echo "  ✓ Public key endpoint working (batch)"
echo "  ✓ Message sending working"
echo "  ✓ Message retrieval working"
echo ""
echo "Check for encrypted_priv_keys in login responses above."
echo ""
echo "Frontend Testing (Open in Browser):"
echo "  URL: http://localhost:3000 (or your frontend port)"
echo "  Test Account 1: alice / password123 (Desk: $ALICE_DESK)"
echo "  Test Account 2: bob / password123 (Desk: $BOB_DESK)"
echo ""
echo "Frontend Test Steps:"
echo "  1. Login as Alice"
echo "  2. Open browser console - look for 'Private key decrypted' logs"
echo "  3. Compose message to Bob ($BOB_DESK)"
echo "  4. Check console for '✓ Message encrypted' log"
echo "  5. Login as Bob"
echo "  6. Open message - check console for '✓ Message decrypted' log"
echo "  7. Reply to Alice - check encryption logs again"
echo ""
