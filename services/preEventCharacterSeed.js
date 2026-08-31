const PreEventCharacter = require("../models/PreEventCharacter");

const PRE_EVENT_CHARACTERS = [
  {
    slug: "marcus-rault",
    name: "Marcus Rault",
    role: "Founder, Aurum Ventures",
    teaser:
      "The man of the hour. Charming, ambitious, and the reason everyone's here tonight. But the empire he's built may have a crack in the foundation only he knows about.",
  },
  {
    slug: "priya-naidoo",
    name: "Priya Naidoo",
    role: "Lead Investor",
    teaser:
      "She wrote the biggest cheque in the room. Polished, composed, and carrying a secret that could unravel everything if the wrong person starts asking the right questions.",
  },
  {
    slug: "dylan-smit",
    name: "Dylan Smit",
    role: "Corporate Attorney",
    teaser:
      "He wrote the contracts. He knows exactly what's in them, including the part no one else has read closely enough. Yet.",
  },
  {
    slug: "jess-hartley",
    name: "Jess Hartley",
    role: "Tech Founder",
    teaser:
      "Her startup is the fund's star portfolio company. The numbers look great on paper. Jess would very much like them to stay that way.",
  },
  {
    slug: "owen-dreyer",
    name: "Owen Dreyer",
    role: "Financial Journalist",
    teaser:
      "He wasn't on the guest list. Nobody's quite sure how he got in. He's been very interested in the canapés, and everyone's conversations.",
  },
  {
    slug: "candice-louw",
    name: "Candice Louw",
    role: "Events Director",
    teaser:
      "She made tonight happen: the venue, the florals, the champagne. She also knows where every body is buried. Figuratively. Probably.",
  },
  {
    slug: "tashan-govender",
    name: "Tashan Govender",
    role: "CFO & Co-founder",
    teaser:
      "Marcus's right hand. Quiet, measured, and spending a lot of tonight staring at his phone. Something is clearly on his mind.",
  },
  {
    slug: "ria-mostert",
    name: "Ria Mostert",
    role: "Lifestyle Doctor & Investor",
    teaser:
      "She arrived in a very nice car and said very little about where her money comes from. Both of those things are intentional.",
  },
  {
    slug: "luca-van-der-berg",
    name: "Luca van der Berg",
    role: "Brand Strategist",
    teaser:
      "Marcus's oldest friend. He helped build the Aurum brand, and has been avoiding eye contact with Marcus all evening for reasons entirely unrelated to branding.",
  },
  {
    slug: "simone-fick",
    name: "Simone Fick",
    role: "Data Analyst",
    teaser:
      "Three weeks into the job. Already the most dangerous person in the room, though she hasn't decided what to do about it yet.",
  },
];

async function ensurePreEventCharacters() {
  for (const character of PRE_EVENT_CHARACTERS) {
    await PreEventCharacter.findOneAndUpdate(
      { slug: character.slug },
      { $setOnInsert: character },
      { upsert: true, new: true },
    );
  }
}

module.exports = {
  PRE_EVENT_CHARACTERS,
  ensurePreEventCharacters,
};
