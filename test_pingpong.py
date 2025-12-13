#!/usr/bin/env python3

import requests
import json
import time

BASE_URL = "http://localhost:8080"

print("=== Testing Ping-Pong Conversation ===\n")

# Step 1: Login as Alice
print("Step 1: Login as Alice...")
alice_resp = requests.post(f"{BASE_URL}/api/accounts/login", 
    json={"username": "alice", "password": "password123"})
alice_data = alice_resp.json()
alice_token = alice_data.get("token")
alice_desk = alice_data.get("desks", [{}])[0].get("id")
print(f"Alice desk: {alice_desk}\n")

# Step 2: Login as Bob
print("Step 2: Login as Bob...")
bob_resp = requests.post(f"{BASE_URL}/api/accounts/login",
    json={"username": "bob", "password": "password123"})
bob_data = bob_resp.json()
bob_token = bob_data.get("token")
bob_desk = bob_data.get("desks", [{}])[0].get("id")
print(f"Bob desk: {bob_desk}\n")

# Step 3: Alice sends message to Bob
print("Step 3: Alice sends message to Bob...")
conv_resp = requests.post(f"{BASE_URL}/api/conversations?desk_id={alice_desk}",
    headers={"Authorization": f"Bearer {alice_token}"},
    json={
        "to": bob_desk,
        "subject": "Ping-Pong Test", 
        "body": "Message 1 from Alice",
        "font_family": "Arial",
        "font_size": 12
    })
conv_data = conv_resp.json()
alice_conv_id = conv_data.get("conversation", {}).get("id")
print(f"Alice's conversation ID: {alice_conv_id}\n")

time.sleep(1)

# Step 4: Check Bob's conversations
print("Step 4: Check Bob's conversations...")
bob_convs_resp = requests.get(f"{BASE_URL}/api/conversations?desk_id={bob_desk}",
    headers={"Authorization": f"Bearer {bob_token}"})
bob_convs_data = bob_convs_resp.json()
bob_convs = bob_convs_data.get("conversations", [])
if bob_convs:
    bob_conv_id = bob_convs[0].get("id")
    print(f"Bob's conversation ID: {bob_conv_id}\n")
else:
    print("❌ ERROR: Bob has no conversations!\n")
    exit(1)

# Step 5: Check Bob sees the message
print("Step 5: Check Bob sees the message...")
bob_detail_resp = requests.get(f"{BASE_URL}/api/conversations/{bob_conv_id}?desk_id={bob_desk}",
    headers={"Authorization": f"Bearer {bob_token}"})
bob_detail = bob_detail_resp.json()
bob_mivs = bob_detail.get("mivs", [])
print(f"Bob sees {len(bob_mivs)} miv(s)")
if bob_mivs:
    print(f"Bob's first miv: seq={bob_mivs[0].get('seq_no')}, from={bob_mivs[0].get('from')}, state={bob_mivs[0].get('state')}\n")
else:
    print("❌ ERROR: Bob sees no mivs!\n")
    exit(1)

# Step 6: Bob replies to Alice
print("Step 6: Bob replies to Alice...")
reply_resp = requests.post(f"{BASE_URL}/api/conversations/{bob_conv_id}/reply?desk_id={bob_desk}",
    headers={"Authorization": f"Bearer {bob_token}"},
    json={
        "body": "Message 2 from Bob (reply)",
        "font_family": "Arial",
        "font_size": 12
    })
print(f"Reply status: {reply_resp.status_code}\n")

time.sleep(1)

# Step 7: Check Alice sees Bob's reply
print("Step 7: Check Alice sees Bob's reply...")
alice_detail_resp = requests.get(f"{BASE_URL}/api/conversations/{alice_conv_id}?desk_id={alice_desk}",
    headers={"Authorization": f"Bearer {alice_token}"})
alice_detail = alice_detail_resp.json()
alice_mivs = alice_detail.get("mivs", [])
print(f"Alice sees {len(alice_mivs)} miv(s)")
for i, miv in enumerate(alice_mivs):
    print(f"  Miv {i+1}: seq={miv.get('seq_no')}, from={miv.get('from')}, to={miv.get('to')}, state={miv.get('state')}")
print()

# Step 8: Alice replies back
print("Step 8: Alice replies back...")
reply2_resp = requests.post(f"{BASE_URL}/api/conversations/{alice_conv_id}/reply?desk_id={alice_desk}",
    headers={"Authorization": f"Bearer {alice_token}"},
    json={
        "body": "Message 3 from Alice (reply to reply)",
        "font_family": "Arial",
        "font_size": 12
    })
print(f"Reply status: {reply2_resp.status_code}\n")

time.sleep(1)

# Step 9: Check Bob sees Alice's reply
print("Step 9: Check Bob sees Alice's second message...")
bob_detail2_resp = requests.get(f"{BASE_URL}/api/conversations/{bob_conv_id}?desk_id={bob_desk}",
    headers={"Authorization": f"Bearer {bob_token}"})
bob_detail2 = bob_detail2_resp.json()
bob_mivs2 = bob_detail2.get("mivs", [])
print(f"Bob sees {len(bob_mivs2)} miv(s)")
for i, miv in enumerate(bob_mivs2):
    print(f"  Miv {i+1}: seq={miv.get('seq_no')}, from={miv.get('from')}, to={miv.get('to')}, state={miv.get('state')}")
print()

# Final verification
print("=== Final Verification ===")
print(f"Expected: Both Alice and Bob should see 3 messages each")
print(f"Alice sees: {len(alice_mivs)} mivs (should be 2 after Bob's reply)")
print(f"Bob sees: {len(bob_mivs2)} mivs (should be 3)\n")

if len(bob_mivs2) == 3 and len(alice_mivs) == 2:
    print("✅ SUCCESS: Ping-pong conversation working correctly!")
elif len(alice_mivs) < 2:
    print(f"❌ FAILURE: Alice should see 2 messages but sees {len(alice_mivs)}")
    print("   This means Bob's reply didn't reach Alice!")
elif len(bob_mivs2) < 3:
    print(f"❌ FAILURE: Bob should see 3 messages but sees {len(bob_mivs2)}")
    print("   This means Alice's second reply didn't reach Bob!")
else:
    print("✅ Partial success but unexpected message counts")
