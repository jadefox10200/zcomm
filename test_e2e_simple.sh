#!/bin/bash

# Simple E2E Encryption Test
# Verifies backend infrastructure is ready for frontend E2E encryption

API_URL="http://localhost:8080"

echo "🔐 E2E Encryption Infrastructure Test"
echo "======================================"
echo ""

# Test 1: Login returns encrypted private keys
echo "✓ Test 1: Login endpoint returns encrypted_priv_keys"
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/accounts/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "10200mille"}')

if echo "$LOGIN_RESPONSE" | grep -q "encrypted_priv_keys"; then
  echo "  ✅ PASS: encrypted_priv_keys field present"
  ALICE_DESK=$(echo "$LOGIN_RESPONSE" | grep -o '"desks":\["[0-9]*"' | grep -o '[0-9]*')
  echo "  Alice's desk ID: $ALICE_DESK"
else
  echo "  ❌ FAIL: encrypted_priv_keys field missing"
  exit 1
fi
echo ""

# Test 2: Public key endpoint (single)
echo "✓ Test 2: Single public key endpoint"
PUBKEY_RESPONSE=$(curl -s "$API_URL/api/desks/$ALICE_DESK/public-key")

if echo "$PUBKEY_RESPONSE" | grep -q "public_key"; then
  echo "  ✅ PASS: Public key endpoint working"
  PUBKEY=$(echo "$PUBKEY_RESPONSE" | grep -o '"public_key":"[^"]*"' | cut -d'"' -f4)
  echo "  Public key length: ${#PUBKEY} characters"
else
  echo "  ❌ FAIL: Public key endpoint not working"
  exit 1
fi
echo ""

# Test 3: Batch public key endpoint
echo "✓ Test 3: Batch public key endpoint"
BOB_DESK="9313041142"
BATCH_RESPONSE=$(curl -s -X POST "$API_URL/api/desks/public-keys" \
  -H "Content-Type: application/json" \
  -d "{\"desk_ids\": [\"$ALICE_DESK\", \"$BOB_DESK\"]}")

if echo "$BATCH_RESPONSE" | grep -q "public_keys"; then
  echo "  ✅ PASS: Batch public key endpoint working"
  NUM_KEYS=$(echo "$BATCH_RESPONSE" | grep -o '"public_key"' | wc -l | tr -d ' ')
  echo "  Retrieved $NUM_KEYS public keys"
else
  echo "  ❌ FAIL: Batch public key endpoint not working"
  exit 1
fi
echo ""

echo "======================================"
echo "✅ All Backend Tests Passed!"
echo "======================================"
echo ""
echo "Backend is ready for E2E encryption."
echo ""
echo "Next Steps - Frontend Testing:"
echo "------------------------------"
echo "1. Start frontend: cd frontend && npm start"
echo "2. Open http://localhost:3000 in browser"
echo "3. Open browser DevTools console"
echo "4. Login as Alice (username: alice, password: 10200mille)"
echo "5. Look for console logs:"
echo "   - 'Private key decrypted and stored for desk: XXXX'"
echo "6. Compose message to Bob (desk: $BOB_DESK)"
echo "7. Look for console log:"
echo "   - '✓ Message encrypted for recipient'"
echo "8. Logout and login as Bob (username: bob, password: 10200mille)"
echo "9. Open the message from Alice"
echo "10. Look for console log:"
echo "   - '✓ Message decrypted successfully'"
echo "11. Click Reply and send a reply"
echo "12. Look for console log:"
echo "   - '✓ Reply encrypted for recipient'"
echo ""
echo "Expected Behavior:"
echo "-----------------"
echo "- Messages should show 🔒 End-to-end encrypted indicator"
echo "- Message bodies should be readable (decrypted automatically)"
echo "- No decryption errors in console"
echo "- All encryption/decryption should be automatic"
echo ""
