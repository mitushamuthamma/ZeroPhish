| # | Attack | What the thief does | Expected | Actual | Result |
|---|---|---|---|---|---|
| 1 | Normal login (control) | Nothing - honest user on the real site | accepted | accepted | ALLOWED (as intended) |
| 2 | Replay a used login | Sends the exact same nonce + signature again | challenge_used | challenge_used | BLOCKED |
| 3 | Phishing relay (honest thief) | Fake site forwards the victim's login to the real server | wrong_domain | wrong_domain | BLOCKED |
| 4 | Reuse the signature stolen by the phishing site | Thief takes the signature from the line above and tries it directly on the real server | challenge_used | challenge_used | BLOCKED |
| 5 | Phishing relay that LIES about the address | Thief rewrites the origin to the real address, keeping the fake-site signature | invalid_signature | invalid_signature | BLOCKED |
| 6 | Tampered signature | Flips one bit of a valid signature | invalid_signature | invalid_signature | BLOCKED |
| 7 | Thief's own key | Signs correctly, but with the thief's key instead of the victim's | invalid_signature | invalid_signature | BLOCKED |
| 8 | Made-up challenge | Invents a nonce the server never issued | unknown_challenge | unknown_challenge | BLOCKED |
| 9 | Sensitive action without logging in | Asks for an action challenge with no session | unauthorized | unauthorized | BLOCKED |
| 10 | Approve a sensitive action (control) | Nothing - honest user changes email | accepted | accepted | ALLOWED (as intended) |
| 11 | Replay an approved action | Sends the same action signature again | challenge_used | challenge_used | BLOCKED |
| 12 | Change the details after signing | Victim signed 'new@mail.com', thief swaps in 'evil@mail.com' | invalid_signature | invalid_signature | BLOCKED |
| 13 | Use a LOGIN challenge to approve an action | Tries to turn a login signature into a transfer approval | wrong_purpose | wrong_purpose | BLOCKED |
| 14 | Phishing site tricks victim into approving a transfer | Fake site relays the 'approve transfer' request | wrong_domain | wrong_domain | BLOCKED |
| 15 | Use an expired login challenge | Waits over 60 seconds, then sends a valid signature | challenge_expired | challenge_expired | BLOCKED |
| 16 | Use an expired action challenge | Waits over 30 seconds, then sends a valid signature | challenge_expired | challenge_expired | BLOCKED |
