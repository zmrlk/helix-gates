# Design

ASSUMPTION: blocked until source brand is approved. Replace projection with exactly the approved brand colors and fonts.

```json
{"colors": [], "fonts": []}
```

ASSUMPTION: design workflow after approved brand intake:
1. Inventory key screens/flows for mobile and web. Adapt `new/templates/design-references.json.tpl`;
   retain 3–5 distinct pattern links and rationale for each flow (M+ audit control).
   Sources may include Mobbin, Refero, Appshots, 60fps and UI Sources.
2. Never copy third-party branding/assets. Brand colors, fonts, logos and assets
   always come from approved brand intake. A style preset only layers density,
   composition and motion onto that brand; record rationale and owner choice.
3. After a usable prototype, after material flow changes and before handoff,
   complete `new/templates/ux-review.md.tpl` using existing UX/consistency probes.
   A static review cannot satisfy runtime verification.
