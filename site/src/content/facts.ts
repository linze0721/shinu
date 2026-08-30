/**
 * Single source of truth for every string on the site.
 *
 * Voice: assertive, atmospheric, benefit-first. The page sells the sensation
 * of working without consequences, not the implementation that delivers it.
 *
 * Provenance rules:
 * - Numbers are transcribed from the repository and cited inline. The framing
 *   around them is marketing; the figures themselves are never invented.
 * - Brand and contact details come from the product owner, not the repo.
 * - Anything unconfirmed is null and its consumers are guarded, so an
 *   unverified value can never render as a dead link.
 * - Implementation names (the hypervisor, the filesystem, the transport) are
 *   deliberately absent from visible copy.
 */

export const brand = {
  name: "shinu",
  parent: "Sylvonic AI",
  parentLine: "Presented by Sylvonic AI",
  /** Supplied directly by the product owner. */
  contact: "start@sylvonic.com",
} as const;

/**
 * No public source URL is confirmed. The git remote is an internal host,
 * and no public mirror is documented anywhere in the repo. Set this to a real
 * public URL to render the source links again; every consumer is guarded on
 * it, so leaving it null simply omits them.
 */
export const repo: string | null = null;

export const meta = {
  title: "shinu: nothing your agent does is permanent",
  description:
    "Whole machines that rewind. Freeze any moment, take back any mistake, and run every branch of the future at the same time.",
} as const;

export const hero = {
  eyebrow: "shinu / Sylvonic AI",
  headlineTop: "Nothing your agent does",
  headlineEmphasis: "is permanent",
  subtext:
    "Whole machines that rewind. Freeze any moment, take it back, and run every future at once.",
  ctaPrimary: "Request access",
  ctaSecondary: "See what it does",
} as const;

/** README.md:5, 60 — every figure below is measured, only the framing is new. */
export const timings = {
  cold: "1.7 s",
  hot: "0.4 s",
  create: "0.14 s",
  createSize: "84 KiB",
} as const;

/** The four verbs, sold as powers rather than API surface. */
export const primitives = [
  {
    verb: "summon",
    signature: "shinu new",
    title: "A machine out of nothing",
    body: "Ask, and a full machine exists. Not a container pretending to be one. A real one, with its own kernel, its own disk, its own life. It arrives faster than you can finish reading this sentence.",
  },
  {
    verb: "freeze",
    signature: "shinu commit",
    title: "Stop time",
    body: "Pin the machine exactly as it is. Every installed package, every half-written file, every process that got it here. The moment keeps, and it costs almost nothing to keep it.",
  },
  {
    verb: "rewind",
    signature: "shinu checkout",
    title: "Take it back",
    body: "Any moment you froze, you can return to. The catastrophic command, the corrupted state, the hour of work that went the wrong way. It simply never happened.",
  },
  {
    verb: "multiply",
    signature: "shinu fork",
    title: "Run every future at once",
    body: "Take one moment and let it become four. Four machines, identical at birth, diverging in parallel. Try every idea simultaneously and keep only the one that worked.",
  },
] as const;

/** The narrative payoff. */
export const workflow = {
  heading: "How it feels to work without consequences",
  lede: "Five moves. The fourth is the one that changes everything.",
  steps: [
    {
      n: "01",
      title: "It appears",
      body: "You ask for a machine. It is already there.",
    },
    {
      n: "02",
      title: "It becomes valuable",
      body: "Dependencies, builds, hours of accumulated context. The kind of state nobody wants to reconstruct twice.",
    },
    {
      n: "03",
      title: "You pin the moment",
      body: "One command and this exact machine is preserved. Not a backup you hope restores. The moment itself.",
    },
    {
      n: "04",
      accent: true,
      title: "It goes catastrophically wrong",
      body: "Something deletes what it should not have. Then you rewind, and it never happened. The failed attempt is still there if you want to study it.",
    },
    {
      n: "05",
      title: "You stop choosing",
      body: "Split the last good moment four ways and run every hypothesis at the same time. Keep the winner. The rest evaporate.",
    },
  ],
  closing:
    "Agents fail constantly. That stops being expensive the moment failure is reversible.",
} as const;

/**
 * README.md:112-125, 397-401 — the posture, stated without the mechanism.
 *
 * Rendered as an acrostic: the initials spell SHINU down the left edge, so
 * the section states the isolation promise and the product name at once.
 * Each `line` MUST begin with its `letter`, or the column stops spelling.
 */
export const isolation = {
  heading: "Five letters, five promises",
  lede: "Every machine runs alone, in the dark, behind a door it cannot open. Read the first letter of each line.",
  points: [
    {
      letter: "S",
      line: "Silent to everything but you",
      body: "It reaches your command channel and nothing else. Cut it off from every network on the box and it still answers.",
    },
    {
      letter: "H",
      line: "Held apart from everything around it",
      body: "Stripped of privilege, walled off from the host and from its neighbours, with hard ceilings on what it can take.",
    },
    {
      letter: "I",
      line: "Invisible to anyone but its owner",
      body: "Ask about a machine that is not yours and it simply does not exist. No permission error left behind to probe at.",
    },
    {
      letter: "N",
      line: "Nothing it does escapes the box",
      body: "Whatever happens in there, happens in there. The blast radius is one machine, and that machine is replaceable.",
    },
    {
      letter: "U",
      line: "Undone the moment you are finished",
      body: "Delete it and it is gone. No residue on the host, no half-cleaned state waiting for whoever comes next.",
    },
  ],
} as const;

/** README.md:5, 60 — measured figures, reframed as spectacle. */
export const measurements = [
  {
    figure: timings.create,
    label: "to conjure a machine",
    body: "From nothing to a machine of your own, faster than a keystroke registers.",
  },
  {
    figure: timings.cold,
    label: "from cold to running",
    body: "A full boot, kernel and all, in less time than it takes to switch tabs.",
  },
  {
    figure: timings.hot,
    label: "to wake one back up",
    body: "Machines sleep when idle and return the instant you speak to them.",
  },
  {
    figure: timings.createSize,
    label: "is what a clone costs",
    body: "Copy an entire machine and pay in kilobytes. Branch it as often as you like.",
  },
] as const;

export const start = {
  heading: "This is not open to everyone yet",
  lede: "Tell us what you are building. If it is the kind of thing that breaks machines, we want to hear about it.",
  cta: "Start by email",
  aside: "Access, hosting, and pilots.",
} as const;
