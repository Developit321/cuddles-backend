# Invitable — Push Notification Copy

---

## 🔔 Daily Limits Overview

| Type | Limit | Reason |
|---|---|---|
| New table created nearby | **Unlimited** *(current growth stage)* | Low user density — every table needs maximum reach |
| Transactional (joins, full, waitlist, 1hr reminder, ratings) | **Unlimited** | User-initiated, always expected |
| FOMO / social (60% full, filling fast, matched person hosting) | **3 per day** | Enough variety; more than 3 feels noisy |
| Re-engagement (weekend nudge, inactive host/guest) | **1 per week** | Loses meaning if repeated too often |
| Post-experience (rate the host) | **Once per table, no follow-up** | Send 2hrs after; if ignored, let it go |

> **Global cap:** Max **3 notifications per user per day** across all non-transactional types.
> If a user already received a transactional notification that day, skip re-engagement and discovery nudges entirely.

---

## 🪑 For Hosts — Creating a Table

| Trigger | Title | Body | Limit | Notes |
|---|---|---|---|---|
| Host publishes a new table → notify nearby users | **Someone near you just made plans** | [Name] is hosting [activity] nearby — [X] spots open. Pull up a chair. | **Unlimited** | Broadcast to all users within radius immediately |
| First person joins their table | **Someone's in!** | [Name] just pulled up a chair. Your table is getting started 🪑 | Unlimited (transactional) | |
| Table reaches 60% capacity (6/10 joined) | **Your table is heating up 🔥** | 6 out of 10 seats are taken — only 4 spots left. | Unlimited (transactional) | Also re-notify nearby users who haven't joined yet |
| Table is full (10/10) | **Full house!** | Your table is packed. See who's coming and get ready. | Unlimited (transactional) | |
| Table ends, no new table in 48hrs | **People had a great time.** | Ready to host again? Your next table is one tap away. | Once per completed table | Only if no new table created within 48hrs |
| Host has been inactive for 2 weeks | **Your crew is waiting.** | What are you planning next? Create a table and see who shows up. | 1 per week | Snooze 2 weeks after sending |

---

## 👀 For Guests — Joining a Table

| Trigger | Title | Body | Limit | Notes |
|---|---|---|---|---|
| New table created nearby | **Someone near you just made plans** | [Name] is hosting [activity] nearby — [X] spots open. Pull up a chair. | **Unlimited** | Same broadcast as above |
| Table nearby is 60% full and guest hasn't joined | **[Name]'s [activity] is filling up fast** | Grab a chair before it's gone. | 1 per day | Only send the most urgent one if multiple tables qualify |
| Friday or Saturday with no table joined | **Nothing on your weekend yet.** | There's a table for that. See what's happening near you. | 1 per week | Skip if user already got a transactional notification that day |
| Guest attends their first table | **That was your first table 🎉** | There are more like it waiting. What do you want to do next? | Once ever | |
| A person they've met before creates a table | **[Name] is hosting something** | They're planning [activity] near you — you've met before. You in? | 1 per day | Prioritised above generic discovery notifications |

---

## 🔥 Social Proof & FOMO

| Trigger | Title | Body | Limit | Notes |
|---|---|---|---|---|
| A nearby table is filling fast (60%+ in under 30 mins) | **This table is blowing up** | 6 people joined in under 30 minutes. A few spots left — move fast. | 1 per day | |
| A highly-rated host creates a table | **A top host just made plans** | [Name] (⭐️ 4.9) is hosting [activity] near you. They always show up. | **Unlimited** | Treated as a new table creation notification |
| User has attended 0 tables after 7 days | **People are out there.** | Real plans, real people — close to you. Your first table is waiting. | 1 per week | |

---

## ⭐️ Post-Experience Loop

| Trigger | Title | Body | Limit | Notes |
|---|---|---|---|---|
| 2 hours after table ends (for guests) | **How was it?** | Rate [Host Name]'s table and help others know who to trust. | Once per table, no follow-up | If ignored within 24hrs, don't resend |
| Guest submits a positive rating | **Glad you had fun.** | Why not host one next time? It only takes a minute to create a table. | Once per rating | |
| Guest attends 3+ tables, never hosted | **You've been to [X] tables.** | Ever thought about hosting one? Your people are already out there. | 1 per week | |
| Host receives their 3rd rating | **Your reputation is building 🏆** | [X] people have rated your tables. Keep going — consistency gets noticed. | Once at 3rd rating milestone | |

---

## 📋 Notification Language Principles

- **Be specific** — always mention the activity type or person's name, never just "a table"
- **Create social tension** — seats left, people joining, filling fast = urgency without spam
- **Stay warm** — "pull up a chair" not "join event"; "your crew" not "other users"
- **End with action** — every notification implies one clear next tap
- **Respect the loop** — host creates → guest joins → experience happens → rating → host again

---

## 🚦 Priority Queue (when multiple notifications are queued same day)

When a user has multiple notifications pending, send in this order and stop at the daily cap:

1. **Transactional** — table updates, joins, ratings, 1hr reminder
2. **Social** — someone they've met is hosting nearby
3. **New table nearby** — *(unlimited at current stage)*
4. **FOMO** — table filling fast
5. **Re-engagement** — weekend nudge, inactivity reminders

> If a user already received a transactional notification that day → skip categories 4 and 5.

---

## 👤 User scenarios — What users actually see

Below is every scenario from the user’s perspective: who gets the notification and what the push looks like (title + body).

### As a **host**

| # | When | What they see (push) |
|---|------|----------------------|
| H1 | They publish a new table | *(They don’t get a push for this; nearby guests get H1-guest.)* |
| H2 | First person joins their table | **Someone's in!** — Alex just pulled up a chair. Your table is getting started 🪑 |
| H3 | Table hits 60% (e.g. 6/10) | **Your table is heating up 🔥** — 6 out of 10 seats are taken — only 4 spots left. |
| H4 | Table is full (10/10) | **Full house!** — Your table is packed. See who's coming and get ready. |
| H5 | Table ended, no new table in 48hrs | **People had a great time.** — Ready to host again? Your next table is one tap away. |
| H6 | Inactive as host for 2 weeks | **Your crew is waiting.** — What are you planning next? Create a table and see who shows up. |
| H7 | They get their 3rd rating | **Your reputation is building 🏆** — 3 people have rated your tables. Keep going — consistency gets noticed. |

---

### As a **guest** — Discovery & joining

| # | When | What they see (push) |
|---|------|----------------------|
| G1 | New table created nearby (any host) | **Someone near you just made plans** — Jordan is hosting Coffee nearby — 8 spots open. Pull up a chair. |
| G2 | New table by someone they matched with  before | **[Name] is hosting something** — They're planning Coffee near you — you've met before. You in? |
| G3 | Nearby table is 60% full and they haven’t joined | **[Jordan]'s Coffee is filling up fast** — Grab a chair before it's gone. |
| G4 | Friday/Saturday and they have no table joined | **Nothing on your weekend yet.** — There's a table for that. See what's happening near you. |
| G5 | They get a direct invite (suggestion) | *(Uses activity_suggestion: e.g. "Jordan wants to do Coffee with you" or "Jordan invited you and 2 others to Coffee".)* |

---

### As a **guest** — FOMO & social proof

| # | When | What they see (push) |
|---|------|----------------------|
| G6 | A nearby table filled fast (60%+ in &lt;30 min) | **This table is blowing up** — 6 people joined in under 30 minutes. A few spots left — move fast. |
| G7 | A highly-rated host creates a table | **A top host just made plans** — Sam (⭐️ 4.9) is hosting Hiking near you. They always show up. |
| G8 | They’ve attended 0 tables after 7 days | **People are out there.** — Real plans, real people — close to you. Your first table is waiting. |

---

### As a **guest** — During & after the table

| # | When | What they see (push) |
|---|------|----------------------|
| G9 | ~1 hour before a table they’re in | **Activity starting soon** — Your activity "Coffee" starts in 1 hour. *(transactional)* |
| G10 | First table they ever attended just ended | **That was your first table 🎉** — There are more like it waiting. What do you want to do next? |
| G11 | 2 hours after a table ended (rate host) | **How was it?** — Rate Jordan's table and help others know who to trust. |
| G12 | They just submitted a positive rating | **Glad you had fun.** — Why not host one next time? It only takes a minute to create a table. |
| G13 | They’ve been to 3+ tables and never hosted | **You've been to 4 tables.** — Ever thought about hosting one? Your people are already out there. |

---

### Example **day in the life**

- **Host, active:**  
  Morning: **Someone's in!** (first join). Midday: **Your table is heating up 🔥** (60%). Afternoon: **Full house!** Next day: **How was it?** (rate) — then **Your reputation is building 🏆** at 3rd rating.

- **Guest, casual:**  
  Tuesday: **Someone near you just made plans** (new table). Friday: **Nothing on your weekend yet.** (re-engagement). Same day: **Jordan's Coffee is filling up fast** (FOMO, 1 of 3 that day allowed).

- **Guest, multi-event same day:**  
  **Activity starting soon** for Event A, then for Event B, then for Event C (all allowed — transactional). Later: **How was it?** for Event A only once; no follow-up if they ignore it.

- **Guest, at FOMO cap:**  
  They already got 3 FOMO-style pushes today (e.g. “filling up fast”, “blowing up”, “someone you met is hosting”). No 4th FOMO until tomorrow; transactional (e.g. 1hr reminder, rate host) still goes through.