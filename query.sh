#!/bin/bash

# Update the BASE_URL or supply it when running the query

curl -X 'GET' \
  'https://$BASE_URL/list?limit=2000&sort=published&minScore=8.0&maxScore=10&year=2025' \
  -H 'accept: application/json' | jq 'map(select(.. | strings | test("mongodb"; "i")))'
