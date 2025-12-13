#!/bin/bash
# Test what JSON the frontend sends
echo "Testing JSON parsing..."
curl -X POST 'http://localhost:8080/api/conversations?desk_id=9139331482' \
  -H 'Content-Type: application/json' \
  -d '{
    "to": "3025161301",
    "subject": "Test Subject",
    "body": "Test Body",
    "font_family": "Georgia, serif",
    "font_size": "14px",
    "line_height": "1.0"
  }' | jq .
