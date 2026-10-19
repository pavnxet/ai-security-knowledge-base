# BUILD_REPORT — secure-kb v0.2.1

Cards: **2108** · Sources: **67** · content_hash `16240f2088f01615`

## Cards by extraction / origin
| extraction | cards |
|---|---|
| programmatic | 2093 |
| authored | 15 |

Origin: distilled=2093, authored=15

Verified: True=2108

## Cards by platform
| platform | cards |
|---|---|
| web | 1869 |
| api | 783 |
| mobile | 58 |
| web3 | 49 |
| vibe | 39 |
| android | 19 |
| cloud | 16 |
| ios | 15 |
| iot | 13 |
| llm | 10 |
| telegram | 7 |
| browser-ext | 4 |
| desktop | 4 |

## Cards by severity / domain
| severity | cards |
|---|---|
| high | 1249 |
| medium | 823 |
| critical | 36 |

Domains: config=492, auth=393, injection=237, logging=115, access-control=112, session=109, secrets=94, xss=80, crypto=63, rate-limiting=63, input-validation=59, file-upload=50

## Coverage matrix (platform x domain, non-empty)
| platform | domains |
|---|---|
| android | config(6), input-validation(4), network(4), storage(3), auth(1), crypto(1) |
| api | config(254), auth(106), injection(78), xss(44), secrets(38), session(33), crypto(31), input-validation(25), file-upload(22), logging(21), rate-limiting(19), csrf(17), api(16), access-control(14), headers(13), data-protection(13), smart-contract(10), ssrf(10), deserialization(8), network(6), storage(3), supply-chain(2) |
| browser-ext | config(2), input-validation(1), xss(1) |
| cloud | config(8), access-control(3), rate-limiting(2), logging(1), auth(1), network(1) |
| desktop | config(1), input-validation(1), headers(1), supply-chain(1) |
| ios | config(5), storage(4), crypto(2), network(2), auth(1), input-validation(1) |
| iot | auth(6), logging(3), config(2), secrets(1), crypto(1) |
| llm | llm(10) |
| mobile | config(22), input-validation(9), storage(9), network(8), auth(5), crypto(5) |
| telegram | secrets(1), webhook(1), network(1), input-validation(1), access-control(1), rate-limiting(1), auth(1) |
| vibe | auth(12), injection(6), secrets(5), access-control(5), config(3), rate-limiting(3), session(2), input-validation(1), xss(1), headers(1) |
| web | config(419), auth(357), injection(229), session(106), logging(104), access-control(97), secrets(81), xss(78), crypto(56), rate-limiting(53), file-upload(49), input-validation(44), csrf(36), headers(25), smart-contract(20), network(20), supply-chain(18), ssrf(18), api(16), deserialization(16), data-protection(13), privacy(8), storage(6) |
| web3 | config(13), logging(6), auth(6), smart-contract(5), rate-limiting(4), secrets(4), storage(3), access-control(3), input-validation(2), crypto(1), supply-chain(1), file-upload(1) |

## Source -> card counts (top 20)
| source | cards |
|---|---|
| OWASP/CheatSheetSeries | 1040 |
| yesmayank/secure-coding-baseline | 447 |
| OWASP/ASVS | 339 |
| OWASP/wstg | 112 |
| OWASP/mastg | 92 |
| raroque/vibe-security-skill | 39 |
| kadenzipfel/smart-contract-vulnerabilities | 38 |
| OWASP/masvs | 24 |
| OWASP/owasp-istg | 19 |
| shieldfy/API-Security-Checklist | 13 |
| crytic/not-so-smart-contracts | 11 |
| OWASP/API-Security | 10 |
| OWASP/Top10 | 10 |
| OWASP/www-project-top-10-for-large-language-model-applications | 10 |
| mgreiler/secure-code-review-checklist | 8 |

Sources contributing 0 cards: Az0x7/vulnerability-Checklist, ConsenSysDiligence/smart-contract-best-practices, CyberSunil/LLMVault, ErdemOzgen/DevSecOps-Vault, Eyadkelleh/awesome-skills-security, GitGuardian/ggshield, Hack-with-Github/Awesome-Hacking, Hrishikesh7665/Android-Pentesting-Checklist, MahdiMashrur/Awesome-Application-Security-Checklist, MobSF/Mobile-Security-Framework-MobSF, OWASP/NodeGoat, OWASP/SecurityShepherd, RedHatInsights/secure-coding-checklist, WebGoat/WebGoat, ahmed313x/OWASP-Web-Checklist, ashishb/android-security-awesome, astoj/vibe-security, benavlabs/vibe-check, danish296/codevibes, dependency-check/DependencyCheck, digininja/DVWA, drego85/tosint, dwisiswant0/apkleaks, e-m-b-a/emba, erev0s/VAmPI, firetix/vibe-coding-penetration-tester, fkie-cad/awesome-embedded-and-iot-security, github/secure_headers, gitleaks/gitleaks, helmetjs/helmet, hysnsec/awesome-policy-as-code, hysnsec/awesome-threat-modelling, infoslack/awesome-web-hacking, juice-shop/juice-shop, lissy93/personal-security-checklist, m14r41/PentestingChecklist, mfkocalar/OWASP-Security-Skills, mvt-project/mvt, nyanko-vn/Secure-AI-Toolkit, paragonie/awesome-appsec

## License outcomes
| ingest outcome | licenses |
|---|---|
| derive | CC-BY-SA-4.0=10, NOASSERTION=9, MIT=7, Apache-2.0=2 |
| reference-only | MIT=5, NOASSERTION=4, CC0-1.0=4, Apache-2.0=1, NONE=1 |
| tool-adapter | Apache-2.0=5, MIT=5, GPL-3.0=3, NOASSERTION=1, LGPL-2.1=1, AGPL-3.0=1 |
| fixture | MIT=4, GPL-3.0=2, NOASSERTION=1, Apache-2.0=1 |

## Benchmark (frozen; expected = official refs)
| set | n | recall@5 | recall@10 | MRR | p50 ms |
|---|---|---|---|---|---|
| all | 154 | 0.61 | 0.649 | 0.57 | 66.11 |
| curated | - | - | - | - | - |
| templated | 95 | 0.789 | 0.811 | 0.755 | 79.33 |
| user | 0 | - | - | - | - |

Lab coverage: 29/30 classes (96.7%); in fast gate 15 (50.0%).

## Known weaknesses
- fix/detect fields on standards-derived cards are source pointers / heuristics, not extracted remediation.
- domain inference is keyword-based; 'config' is over-assigned.
- curated benchmark expected refs include pre-2023 WSTG codes and ASVS v4 numbering -> understated recall (benchmark defect).
- authored platforms (telegram/desktop) have a single authoritative source -> confidence low.
