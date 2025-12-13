#!/bin/bash

# Test script for ping-pong conversation between Alice and Bob
# This tests that replies work correctly with separate conversations

BASE_URL="http://localhost:8080"

echo "=== Testing Ping-Pong Conversation ==="
echo ""

# Step 1: Login as Alice
echo "Step 1: Login as Alice..."
ALICE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/accounts/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}')

ALICE_TOKEN=$(echo $ALICE_RESPONSE | jq -r '.token')
ALICE_DESK=$(echo $ALICE_RESPONSE | jq -r '.desks[0].id')
echo "Alice desk: $ALICE_DESK"
echo ""

# Step 2: Login as Bob
echo "Step 2: Login as Bob..."
BOB_RESPONSE=$(curl -s -X POST "$BASE_URL/api/accounts/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"password123"}')

BOB_TOKEN=$(echo $BOB_RESPONSE | jq -r '.token')
BOB_DESK=$(echo $BOB_RESPONSE | jq -r '.desks[0].id')
echo "Bob desk: $BOB_DESK"
echo ""

# Step 3: Alice sends message to Bob
echo "Step 3: Alice sends message to Bob..."
CONV_RESPONSE=$(curl -s -X POST "$BASE_URL/api/conversations?desk_id=$ALICE_DESK" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d "{\"to\":\"$BOB_DESK\",\"subject\":\"Ping-Pong Test\",\"body\":\"Message 1 from Alice\",\"font_family\":\"Arial\",\"font_size\":12}")

ALICE_CONV_ID=$(echo $CONV_RESPONSE | jq -r '.conversation.id')
echo "Alice's conversation ID: $ALICE_CONV_ID"
echo ""

# Wait a bit
sleep 1

# Step 4: Check Bob's conversations
echo "Step 4: Check Bob's conversations..."
BOB_CONVS=$(curl -s -X GET "$BASE_URL/api/conversations?desk_id=$BOB_DESK" \
  -H "Authorization: Bearer $BOB_TOKEN")

BOB_CONV_ID=$(echo $BOB_CONVS | jq -r '.conversations[0].id')
echo "Bob's conversation ID: $BOB_CONV_ID"
echo ""

# Step 5: Check Bob sees the message
echo "Step 5: Check Bob sees the message..."
BOB_CONV_DETAIL=$(curl -s -X GET "$BASE_URL/api/conversations/$BOB_CONV_ID?desk_id=$BOB_DESK" \
  -H "Authorization: Bearer $BOB_TOKEN")

BOB_MIVS_COUNT=$(echo $BOB_CONV_DETAIL | jq '.mivs | length')
echo "Bob sees $BOB_MIVS_COUNT miv(s)"
echo "Bob's first miv:"
echo $BOB_CONV_DETAIL | jq '.mivs[0] | {seq_no, from, to, subject, state}'
echo ""

# Step 6: Bob replies to Alice
echo "Step 6: Bob replies to Alice..."
REPLY_RESPONSE=$(curl -s -X POST "$BASE_URL/api/conversations/$BOB_CONV_ID/reply?desk_id=$BOB_DESK" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -d '{"body":"Message 2 from Bob (reply)","font_family":"Arial","font_size":12}')

echo "Reply created"
echo ""

# Wait a bit
sleep 1

# Step 7: Check Alice sees Bob's reply
echo "Step 7: Check Alice sees Bob's reply..."
ALICE_CONV_DETAIL=$(curl -s -X GET "$BASE_URL/api/conversations/$ALICE_CONV_ID?desk_id=$ALICE_DESK" \
  -H "Authorization: Bearer $ALICE_TOKEN")

ALICE_MIVS_COUNT=$(echo $ALICE_CONV_DETAIL | jq '.mivs | length')
echo "Alice sees $ALICE_MIVS_COUNT miv(s)"
echo "Alice's mivs:"
echo $ALICE_CONV_DETAIL | jq '.mivs[] | {seq_no, from, to, subject, state}'
echo ""

# Step 8: Alice replies back
echo "Step 8: Alice replies back..."
REPLY2_RESPONSE=$(curl -s -X POST "$BASE_URL/api/conversations/$ALICE_CONV_ID/reply?desk_id=$ALICE_DESK" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{"body":"Message 3 from Alice (reply to reply)","font_family":"Arial","font_size":12}')

echo "Reply created"
echo ""

# Wait a bit
sleep 1

# Step 9: Check Bob sees Alice's reply
echo "Step 9: Check Bob sees Alice's second message..."
BOB_CONV_DETAIL2=$(curl -s -X GET "$BASE_URL/api/conversations/$BOB_CONV_ID?desk_id=$BOB_DESK" \
  -H "Authorization: Bearer $BOB_TOKEN")

BOB_MIVS_COUNT2=$(echo $BOB_CONV_DETAIL2 | jq '.mivs | length')
echo "Bob sees $BOB_MIVS_COUNT2 miv(s)"
echo "Bob's mivs:"
echo $BOB_CONV_DETAIL2 | jq '.mivs[] | {seq_no, from, to, subject, state}'
echo ""

# Step 10: Final verification
echo "=== Final Verification ==="
echo "Expected: Both Alice and Bob should see 3 messages each"
echo "Alice sees: $ALICE_MIVS_COUNT mivs initially (should be 2 after Bob's reply)"
echo "Bob sees: $BOB_MIVS_COUNT2 mivs finally (should be 3)"
echo ""

if [ "$BOB_MIVS_COUNT2" -eq "3" ]; then
    echo "✅ SUCCESS: Ping-pong conversation working correctly!"
else
    echo "❌ FAILURE: Ping-pong conversation broken. Bob should see 3 messages but sees $BOB_MIVS_COUNT2"
fi
