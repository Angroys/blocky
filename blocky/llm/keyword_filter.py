"""
Fast keyword-based pre-filter for adult content detection.

Two-tier system:
  1. Domain keywords — unambiguous terms in the domain name itself → instant block
  2. Content keywords — checked against page title + meta + body text, with
     safe-context exclusions to avoid false positives on medical/educational sites
"""

import re

# ── Tier 1: Domain-name keywords ─────────────────────────────────────────────
# If ANY of these appear as a substring in the domain, it's almost certainly
# an adult site. Very low false-positive rate because legitimate sites don't
# put these words in their domain names.

_DOMAIN_KEYWORDS = frozenset({
    # English
    "porn", "xxx", "xvideo", "xnxx", "xhamster", "redtube", "youporn",
    "brazzers", "onlyfans", "chaturbate", "livejasmin", "bongacam",
    "stripchat", "myfreecam", "spankbang", "tube8", "hentai",
    "pornhub", "xvideos", "cam4", "fapdu", "xerotica",
    "sexcam", "porntube", "adultvideo", "camgirl", "camboy",
    "nudelive", "porndig", "pornpic", "sexpic", "fap",
    "pinkdino", "viewgal", "babesource", "elitebabes",
    "bbwporn", "analpic", "crazysex", "auntmia",
    "eporner", "8muses", "rule34", "gelbooru", "danbooru",
    "nhentai", "hanime", "hclip", "sexvid", "xxxbunker",
    "motherless", "imagefap", "slutload", "pictoa",
    "deepthroat", "creampie", "gangbang", "cumshot",
    "bukkake", "bondage", "hardcore", "softcore",
    "threesome", "foursome", "orgy", "milf",
    "naughtyamerica", "bangbros", "realitykings",
    "mofos", "tushy", "blacked", "vixen",
    "nubile", "hegre", "metart", "femjoy",
    "suicidegirl", "playboyplus", "penthouse",
    "hustler", "wickedpictures", "digitalplayground",
    "jav", "javhd", "uncensored", "hclips",
    "tnaflix", "drtuber", "voyeurhit", "txxx",
    "fuq", "beeg", "youjizz", "jizzbunker",
    "ixxx", "xfree", "xmovie", "porndoe", "porcore",
    "4tube", "sunporno", "anysex", "gotporn", "sexvid",
    "definebabe", "watchmygf", "anon-v", "sxyprn",
    "daftsex", "hqporner", "3movs", "fapcat",
    # Spanish
    "porno", "sexo", "desnuda",
    # French
    "sexe", "coquin",
    # German
    "ficken", "nackt",
    # Portuguese
    "putaria", "safada",
    # Russian (transliterated)
    "porno", "seks",
    # Japanese (romanized)
    "eromanga", "ero",
})

# ── Tier 2: Content keywords (title / meta / body text) ─────────────────────
# These can appear in legitimate contexts, so we require:
#   (a) At least one appears in the page TITLE, OR
#   (b) Multiple distinct keywords appear in the body text
#
# Each keyword is a compiled regex with word boundaries to prevent
# "Middlesex" matching "sex", "therapist" matching "rapist", etc.

_CONTENT_KEYWORDS = [
    re.compile(r"\bporn\b", re.I),
    re.compile(r"\bxxx\b", re.I),
    re.compile(r"\bnude[s]?\b", re.I),
    re.compile(r"\bnaked\b", re.I),
    re.compile(r"\bhentai\b", re.I),
    re.compile(r"\bescort\s+service", re.I),
    re.compile(r"\bcam\s*girl", re.I),
    re.compile(r"\bcam\s*boy", re.I),
    re.compile(r"\bstrip\s*tease\b", re.I),
    re.compile(r"\berotic\b", re.I),
    re.compile(r"\bsex\s+video", re.I),
    re.compile(r"\badult\s+video", re.I),
    re.compile(r"\badult\s+content\b", re.I),
    re.compile(r"\bfetish\b", re.I),
    re.compile(r"\bbdsm\b", re.I),
    re.compile(r"\borgasm\b", re.I),
    re.compile(r"\bmasturbat", re.I),
    re.compile(r"\bblowjob\b", re.I),
    re.compile(r"\bhooker\b", re.I),
    re.compile(r"\bescort\s+girl", re.I),
    re.compile(r"\b18\+\s*(only|content|video|site)", re.I),
    re.compile(r"\bverify\s+(your\s+)?age\b", re.I),
    re.compile(r"\byou\s+must\s+be\s+(18|21|of\s+legal\s+age)\b", re.I),
    re.compile(r"\bfull\s+service\b", re.I),
    re.compile(r"\bgirlfriend\s+experience\b", re.I),
    re.compile(r"\blive\s*cam\b", re.I),
    re.compile(r"\bwebcam\s+(model|girl|sex|show)", re.I),
    re.compile(r"\bpussy\b", re.I),
    re.compile(r"\bcock\b", re.I),
    re.compile(r"\banal\s+(sex|porn|video)", re.I),
    re.compile(r"\bmilf\b", re.I),
    re.compile(r"\bdeepthroat\b", re.I),
    re.compile(r"\banal\b", re.I),
    re.compile(r"\bcreampie\b", re.I),
    re.compile(r"\bgangbang\b", re.I),
    re.compile(r"\bthreesome\b", re.I),
    re.compile(r"\bfoursome\b", re.I),
    re.compile(r"\borgy\b", re.I),
    re.compile(r"\bhardcore\b", re.I),
    re.compile(r"\bsoftcore\b", re.I),
    re.compile(r"\bcumshot\b", re.I),
    re.compile(r"\bfacial\s+(cum|cumshot)\b", re.I),
    re.compile(r"\bhandjob\b", re.I),
    re.compile(r"\bfootjob\b", re.I),
    re.compile(r"\btitjob\b", re.I),
    re.compile(r"\bdouble\s+penetration\b", re.I),
    re.compile(r"\bpenetration\b", re.I),
    re.compile(r"\bsquirt(ing)?\b", re.I),
    re.compile(r"\bbondage\b", re.I),
    re.compile(r"\bdominatrix\b", re.I),
    re.compile(r"\bstrap-?on\b", re.I),
    re.compile(r"\bdildo\b", re.I),
    re.compile(r"\bvibrator\b", re.I),
    re.compile(r"\bbukkake\b", re.I),
    re.compile(r"\bjerk\s*off\b", re.I),
    re.compile(r"\bfap\b", re.I),
    re.compile(r"\btwerk(ing)?\b", re.I),
    re.compile(r"\bslut\b", re.I),
    re.compile(r"\bwhore\b", re.I),
    re.compile(r"\bescort\b", re.I),
    re.compile(r"\bcall\s*girl\b", re.I),
    re.compile(r"\bboobs?\b", re.I),
    re.compile(r"\btits?\b", re.I),
    re.compile(r"\bass\s+(fuck|lick|hole)\b", re.I),
    re.compile(r"\bcum\s+(swap|eat|drink|face)\b", re.I),
    re.compile(r"\binter-?racial\s+(porn|sex)\b", re.I),
    re.compile(r"\bstep-?(mom|dad|sis|bro)\b", re.I),
    re.compile(r"\bincest\b", re.I),
    re.compile(r"\bcuckold\b", re.I),
    re.compile(r"\bswinger\b", re.I),
    re.compile(r"\bvoyeur\b", re.I),
    re.compile(r"\bpegging\b", re.I),
    re.compile(r"\bfisting\b", re.I),
    re.compile(r"\bgape\b", re.I),
    re.compile(r"\bclitoris\b", re.I),
    re.compile(r"\bvagina\b", re.I),
    re.compile(r"\bpenis\b", re.I),
    re.compile(r"\berection\b", re.I),
    re.compile(r"\bejaculat", re.I),
    # Spanish
    re.compile(r"\bporno\b", re.I),
    re.compile(r"\bdesnud[ao]s?\b", re.I),
    re.compile(r"\bsexo\s+(video|en\s+vivo)", re.I),
    re.compile(r"\bcontenido\s+adulto\b", re.I),
    re.compile(r"\bchicas\s+calientes\b", re.I),
    # French
    re.compile(r"\bporno\b", re.I),
    re.compile(r"\bsexe\b", re.I),
    re.compile(r"\bnu[es]?\b", re.I),
    re.compile(r"\bcontenu\s+adulte\b", re.I),
    re.compile(r"\bcam\s+coquine\b", re.I),
    # German
    re.compile(r"\bporno\b", re.I),
    re.compile(r"\bnackt\b", re.I),
    re.compile(r"\bficken\b", re.I),
    re.compile(r"\berotik\b", re.I),
    re.compile(r"\bsex\s*film\b", re.I),
    # Portuguese
    re.compile(r"\bporno\b", re.I),
    re.compile(r"\bputaria\b", re.I),
    re.compile(r"\bnua[s]?\b", re.I),
    re.compile(r"\bsafad[ao]s?\b", re.I),
    re.compile(r"\bconteúdo\s+adulto\b", re.I),
    # Russian (Cyrillic)
    re.compile(r"\bпорно\b", re.I),
    re.compile(r"\bсекс\b", re.I),
    re.compile(r"\bголы[ех]\b", re.I),
    re.compile(r"\bэротик[аи]\b", re.I),
    # Japanese / Chinese (no word boundaries needed — CJK has no spaces)
    re.compile(r"アダルト", re.I),      # "adult"
    re.compile(r"エロ動画", re.I),      # "erotic video"
    re.compile(r"無修正", re.I),        # "uncensored"
    re.compile(r"色情", re.I),          # Chinese "pornography"
    re.compile(r"成人视频", re.I),      # Chinese "adult video"
    re.compile(r"成人內容", re.I),      # Chinese "adult content" (traditional)
    re.compile(r"成人内容", re.I),      # Chinese "adult content" (simplified)
    # Arabic
    re.compile(r"\bإباحي", re.I),      # "pornographic"
    re.compile(r"\bجنس\b", re.I),      # "sex"
]

# ── Safe-context patterns ────────────────────────────────────────────────────
# If any of these appear on the page, suppress the keyword match.
# This prevents blocking medical, educational, and news sites.

_SAFE_CONTEXT = [
    re.compile(r"\bsex(ual)?\s+education\b", re.I),
    re.compile(r"\bsex(ual)?\s+health\b", re.I),
    re.compile(r"\breproductive\s+health\b", re.I),
    re.compile(r"\bsexually\s+transmitted\b", re.I),
    re.compile(r"\bmedical\s+(advice|information|journal|research)\b", re.I),
    re.compile(r"\bclinical\s+(trial|study|research)\b", re.I),
    re.compile(r"\bhealth\s*care\s+provider\b", re.I),
    re.compile(r"\bsex\s+therapy\b", re.I),
    re.compile(r"\bconsent\s+education\b", re.I),
    re.compile(r"\bsex\s+trafficking\b", re.I),
    re.compile(r"\bsex\s+worker\s+rights\b", re.I),
    re.compile(r"\bjournalism\b", re.I),
    re.compile(r"\binvestigat(ive|ion)\b", re.I),
    re.compile(r"\bnews\s+(article|report|coverage)\b", re.I),
    re.compile(r"\bwikipedia\.org\b", re.I),
    re.compile(r"\bacademic\b", re.I),
    re.compile(r"\bpeer.reviewed\b", re.I),
    re.compile(r"\buniversity\b", re.I),
    re.compile(r"\banatomy\b", re.I),
    re.compile(r"\bgynaecolog", re.I),
    re.compile(r"\bgynecolog", re.I),
    re.compile(r"\burology\b", re.I),
    re.compile(r"\bobstetr", re.I),
    re.compile(r"\bfertility\s+(clinic|treatment|specialist)\b", re.I),
    re.compile(r"\bpregnancy\b", re.I),
    re.compile(r"\bchildbirth\b", re.I),
    re.compile(r"\bbreastfeeding\b", re.I),
    re.compile(r"\bWebMD\b", re.I),
    re.compile(r"\bMayo\s+Clinic\b", re.I),
    re.compile(r"\bNHS\b"),
    re.compile(r"\bmedline\b", re.I),
]

# Minimum number of distinct content keyword matches needed in body text
# to trigger blocking (when no title match). Higher = fewer false positives.
_MIN_BODY_KEYWORD_HITS = 3


def check_domain(domain: str) -> bool:
    """Return True if the domain name contains an unambiguous adult keyword."""
    d = domain.lower().replace("-", "").replace("_", "")
    return any(kw in d for kw in _DOMAIN_KEYWORDS)


def check_content(title: str, meta: str, body: str) -> tuple[bool, str]:
    """
    Check page text for adult keywords, respecting safe-context exclusions.

    Returns (is_adult, reason).
    """
    full_text = f"{title} {meta} {body}"

    # Check safe context first — if this looks like a medical/educational page, bail
    for pattern in _SAFE_CONTEXT:
        if pattern.search(full_text):
            return False, ""

    # Check title — a keyword in the title is a strong signal
    title_hits = [p for p in _CONTENT_KEYWORDS if p.search(title)]
    if title_hits:
        kw = title_hits[0].pattern.replace(r"\b", "").split("\\")[0]
        return True, f"Adult keyword in page title: {kw!r}"

    # Check body text — require multiple distinct keyword matches
    body_text = f"{meta} {body}"
    body_hits = [p for p in _CONTENT_KEYWORDS if p.search(body_text)]
    if len(body_hits) >= _MIN_BODY_KEYWORD_HITS:
        kws = [p.pattern.replace(r"\b", "").split("\\")[0] for p in body_hits[:3]]
        return True, f"Multiple adult keywords in page content: {', '.join(kws)}"

    return False, ""
