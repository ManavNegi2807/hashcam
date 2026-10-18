# Third-party files served by the pages

The first two are copied unchanged from npm packages; the scroll files below come from the GSAP and Lenis repositories (Lenis's browser build from its npm release, because the repository holds only source). All were downloaded once into a folder outside the project, checked against the registry's
published SHA-512 checksum, and read for network or code-evaluation calls (none). The pages load
nothing from the internet: these files are served from this computer.

| File | Package | Version | Licence | SHA-256 of the file |
|---|---|---|---|---|
| motion.js | `motion` (motion.dev), `dist/motion.js` | 14.0.0 | MIT (LICENSE-motion.md) | cbd68b4c7f906740542503da2f45aa42a511114959eeb116320afc77812a3d04 |
| plus-jakarta-sans.woff2 | `@fontsource-variable/plus-jakarta-sans`, latin subset | 5.3.0 | SIL OFL 1.1 (OFL-plus-jakarta-sans.txt) | 153fc85b70298beeb1d61a5f723331649e7f23bb77302a66e61cb3e2fbdb5e79 |
| gsap.min.js | GSAP repo `dist/` (greensock/GSAP @ 13e2b79) | 3.15.0 | GreenSock Standard 'no charge' (LICENSE-gsap.txt) | dd7dc87e023b3480f9707296342565ca2e361c8393cabb30f9557e06eb1bed4d |
| ScrollTrigger.min.js | same repo, `dist/` | 3.15.0 | same | ba6ffe7b85ddcc7b891b91a430f88640dff41017874bceedf071ca156ccccefa |
| lenis.min.js | `lenis` npm release (source: darkroomengineering/lenis), `dist/` | 1.3.27 | MIT (LICENSE-lenis.txt) | 80f53e77f1c13e379fc246d2b5e299188e20bcb2b2fe7ebb13e8e8c7563a6da7 |
| lenis.css | same package, `dist/` | 1.3.27 | MIT | 2f668ae84a668327f246faf8a770383a2bf69196d214290fbc4d5548910606c5 |

Both versions were at least two weeks old when chosen. To update, download the new package into an
empty folder, verify its checksum, read it, and replace the file and the hashes above.

`react-bits` (DavidHDev) was downloaded and read but **not used**: it is React source, this project has no React, and its licence (MIT + Commons Clause) forbids selling the software itself.
