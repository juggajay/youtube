# Podcast Writing Ruleset v1

## Section 1: Format & Hosts

**Format:** NPR-style news bulletin. Authoritative but warm. Facts speak for themselves.

**Hosts:**
- **Melody** (Host) - Smart tech journalist with a business/risk lens. Guides the conversation, asks questions listeners are thinking, always brings it back to "who cares and what should they do?"
- **Alec** (Expert) - Veteran security analyst. Calm, measured, seen it all. Doesn't hype. When he says something is serious, you believe him.

**Dynamic:** Host + Expert interview. Melody asks, guides, reacts. Alec explains, advises, contextualizes.

**Tone:**
- Credible through understatement, not drama
- Conversational warmth, not stiff
- Treat listeners as smart non-specialists
- Plain language over jargon

---

## Section 2: Episode Structure

**Opening (30 seconds):**
- Melody opens, sets the scene: "Good morning, I'm Melody. With me as always, security analyst Alec. What are you watching today?"
- Alec gives rapid headlines: "One critical issue this morning - Apache servers under active attack. Also on our radar, a WordPress flaw affecting millions of sites."
- Listener knows the stakes immediately. Even if they stop here, they got the essentials.

**Deep Dives (bulk of episode):**
- Take each story in priority order (critical first)
- For each:
  - **Setup**: What's the vulnerability, who's affected
  - **Stakes**: Why it matters, what attackers can do
  - **Action**: What to do about it, how urgent
- Melody and Alec volley - she asks, he explains, she grounds it in business reality

**Wrap-up (30 seconds):**
- Melody recaps: "So the big one today is the Apache issue - patch now. WordPress can wait til end of week."
- Alec adds any final context
- Clean sign-off

**Pacing:** 5-8 minutes total. Don't pad. If it's a quiet day with nothing critical, say so and keep it short.

---

## Section 3: Natural Dialogue

**The Cardinal Rule:** Write like humans actually talk, not like scripts read aloud.

**Interruptions & Reactions:**
- Melody cuts in: "Wait—", "Hold on—", "That's huge.", "Okay so..."
- Alec reacts: "Exactly.", "Right.", "That's the thing.", "Well..."
- Don't wait for perfect pauses. Real conversations overlap.

**Imperfect Transitions:**
- Not every handoff is clean: "So...", "Actually, let me back up.", "And the other thing is..."
- Avoid robotic segues like "Moving on to our next topic..."

**Varying Rhythm:**
- Short punchy exchanges:
  - "How bad?" / "Bad. Patch today."
- Longer explanations when needed
- Mix it up. Same cadence = sleep.

**Contractions & Filler:**
- Use them: "don't", "it's", "we've", "that's"
- Light filler is okay: "you know", "I mean", "look"
- Not too much - still professional

**Questions Melody Would Actually Ask:**
- "Break that down for me."
- "Who should be worried right now?"
- "What's the fix?"
- "How urgent is this really?"

---

## Section 4: Technical Language

**The CVE Rule:**
- Mention CVE ID **once at the start** when introducing the vulnerability
- Reference naturally throughout: "this flaw", "the Apache issue", "it", "this vulnerability"
- Repeat CVE ID **once at the end** for action: "Again, that's CVE-2025-0001 - patch today."
- **Never** say the same CVE ID three times in a row. That's robot talk.

**Version Numbers:**
- State once: "Versions 2.4.0 through 2.4.58 are affected."
- Then: "affected versions", "vulnerable systems", "if you're running Apache"
- Don't keep repeating the range.

**Scores & Metrics:**
- CVSS: Translate it. "CVSS 9.8 - about as bad as it gets." Or just say "critical severity" and skip the number.
- EPSS: Make it real. "45% chance this gets exploited in the wild" not "EPSS score of 0.45"
- Don't stack jargon: "CVSS 9.8, EPSS 0.45, CISA KEV listed" - pick what matters most.

**Plain Language Wins:**
- "Attackers can take over your server" not "enables remote code execution"
- "You need to update" not "remediation requires patching to the latest version"
- "It's being exploited right now" not "active exploitation has been observed"

**Melody's role:** If Alec gets too technical, she pulls him back. "In plain English?"

---

## Section 5: Engagement Without Hype

**Lead With Stakes, Not Specs:**
- Yes: "Attackers are actively exploiting this to take over Apache servers."
- No: "CVE-2025-0001 has a CVSS score of 9.8 and affects Apache HTTP Server."
- The impact hooks them. The specs come after.

**Narrative Structure (subtle):**
- **Setup**: Here's the flaw and who has it
- **Tension**: Here's what attackers can do with it
- **Resolution**: Here's how to fix it
- Don't force it. Let it flow naturally.

**Urgency Through Calm:**
- Alec doesn't shout. He states facts plainly.
- "This is being actively exploited. If you run Apache, stop what you're doing and patch." - calm but clear.
- The understatement makes it hit harder.

**What NOT To Do:**
- No "CRITICAL ALERT" / "BREAKING" drama
- No "you NEED to hear this" / "this is HUGE"
- No fear-mongering: "hackers could destroy your business"
- No clickbait framing

**Let Silence Work:**
- A pause after a serious statement lands harder than shouting
- Melody can react with "...wow" or just "okay" - acknowledges weight without overdoing it

**Quiet Days:**
- If nothing critical, say so: "Relatively quiet day. A few things to keep on your radar, but nothing that needs immediate action."
- Don't inflate minor issues to fill time. Credibility matters more than runtime.
