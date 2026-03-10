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
    # ── Major tube / streaming sites ────────────────────────────────────
    "porn", "pornhub", "xvideo", "xvideos", "xnxx", "xhamster",
    "redtube", "youporn", "tube8", "xtube", "porntube", "porndoe",
    "porndig", "pornpic", "porntrex", "pornrox", "pornone",
    "porndish", "porngo", "pornhat", "pornid", "pornjam",
    "pornktube", "pornlib", "pornmate", "pornmz", "pornobae",
    "pornolab", "pornovoisines", "pornoxo", "pornsos", "porntop",
    "pornzog", "tnaflix", "drtuber", "voyeurhit", "txxx",
    "fuq", "beeg", "youjizz", "jizzbunker", "jizzplanet",
    "ixxx", "xfree", "xmovie", "4tube", "sunporno",
    "anysex", "gotporn", "hclips", "hclip", "hqporner",
    "3movs", "fapcat", "fapdu", "daftsex", "sxyprn",
    "eporner", "spankbang", "spankwire", "slutload",
    "xxxbunker", "xxx", "sexvid", "sextube",
    # ── Premium / studio sites ──────────────────────────────────────────
    "brazzers", "naughtyamerica", "bangbros", "realitykings",
    "mofos", "tushy", "blacked", "vixen", "babes",
    "nubile", "hegre", "metart", "femjoy", "playboy",
    "playboyplus", "penthouse", "hustler", "hustlermagazine",
    "wickedpictures", "digitalplayground", "kink", "girlsway",
    "adultime", "dorcel", "marc-dorcel", "private",
    "twistys", "ztod", "julesjordan", "evilangel",
    "letsdoeit", "fakehub", "faketaxi", "fakehospital",
    "sexyhub", "puremature", "passion-hd", "fantasyhd",
    "castingcouch", "backroom", "exploitedcollegegirls",
    "woodmancastingx", "legalporno", "analvids",
    "swallowed", "throated", "teenflip", "hookuphotshot",
    "blackedraw", "deeper", "slayed", "milfy",
    # ── Cam / live sites ────────────────────────────────────────────────
    "onlyfans", "chaturbate", "livejasmin", "bongacam",
    "stripchat", "myfreecam", "cam4", "camsoda",
    "flirt4free", "streamate", "imlive", "camster",
    "sexcam", "camgirl", "camboy", "nudelive",
    "bimbim", "jerkmate", "rabbits",
    # ── Hentai / anime / drawn ──────────────────────────────────────────
    "hentai", "nhentai", "hanime", "hentaihaven",
    "hentaistream", "hentaimama", "hentaigasm", "hentaiworld",
    "rule34", "gelbooru", "danbooru", "konachan",
    "e-hentai", "exhentai", "hitomi", "pururin",
    "fakku", "tsumino", "luscious", "8muses",
    "multporn", "doujin", "mangahentai",
    # ── Image / gallery sites ───────────────────────────────────────────
    "imagefap", "motherless", "pictoa", "xerotica",
    "viewgal", "babesource", "elitebabes", "definebabe",
    "babepedia", "kindgirls", "erosberry", "hegrehunter",
    "ftvgirls", "suicidegirl", "zishy", "femjoyhunter",
    "pornpic", "sexpic", "analpic",
    "pinkdino", "watchmygf", "anon-v",
    # ── Escort / hookup ─────────────────────────────────────────────────
    "escort", "escortbabylon", "cityxguide", "eros",
    "skipthegames", "megapersonals", "bedpage",
    "adultfriendfinder", "ashleymadison", "fling",
    "hookup", "banglocals", "benaughty",
    # ── Explicit act keywords (domain substrings) ───────────────────────
    "deepthroat", "creampie", "gangbang", "cumshot",
    "bukkake", "blowjob", "handjob", "footjob", "titjob",
    "bondage", "hardcore", "softcore",
    "threesome", "foursome", "orgy", "milf",
    "fap", "cuckold", "incest", "voyeur",
    "fisting", "squirt", "pegging",
    "bbwporn", "crazysex", "auntmia",
    # ── JAV / Asian ─────────────────────────────────────────────────────
    "jav", "javhd", "javlibrary", "javguru", "javbangers",
    "javfinder", "javfull", "javhihi", "javmost", "javplay",
    "uncensored", "caribbeancom", "tokyohot", "1pondo",
    "heyzo", "s-cute",
    # ── Spanish ─────────────────────────────────────────────────────────
    "porno", "sexo", "desnuda", "putita", "follando",
    "culonas", "tetonas", "corridas",
    # ── French ──────────────────────────────────────────────────────────
    "sexe", "coquin", "salope", "beurette",
    # ── German ──────────────────────────────────────────────────────────
    "ficken", "nackt", "schwanz", "titten", "fotze",
    # ── Portuguese ──────────────────────────────────────────────────────
    "putaria", "safada", "gostosa", "bundas",
    # ── Russian (transliterated) ────────────────────────────────────────
    "porno", "seks", "sosalka", "shlyuha",
    # ── Japanese (romanized) ────────────────────────────────────────────
    "eromanga", "oppai", "ecchi",
    # ── Erotic movies / softcore / adult cinema ───────────────────────
    "eroticmovie", "eroticfilm", "erotica",
    "adultmovie", "adultfilm", "adultcinema",
    "sexmovie", "sexfilm", "sexcinema",
    "nakedsword", "hotmovies", "adultdvd",
    "adultvod", "aebn", "adultempire", "gamelink",
    "sexart", "xconfession", "lustery",
    "bellesa", "wowgirls", "ultrafilms", "joymii",
    "nubilefilms", "eroticax", "darkx",
    "eroprofile", "erome", "erothots",
    # ── Other aggregators / link sites ──────────────────────────────────
    "xbabe", "xbef", "xcafe", "xgroovy", "xkeezmovies",
    "xlxx", "xmegadrive", "xpee", "xrares",
    "ashemaletube", "trannytube", "shemale",
    "femdomtube", "bdsmstreak", "fetishpapa",
    "tubegalore", "lobstertube", "thumbzilla",
    "pornmd", "nudevista", "alohatube",
    "vporn", "xbabe", "sexbot", "empflix",
    # ── Compound keywords (catch domains like sexygirlspics, nudepics) ───
    "sexygirl", "sexyteen", "sexymilf", "sexypic", "sexyvid",
    "hotgirl", "hotteen", "hotmilf", "hotnude",
    "nudegirl", "nudeteen", "nudepic", "nudevid", "nudemodel",
    "nakedgirl", "nakedteen", "nakedpic", "nakedwomen",
    "nsfwpic", "nsfwgirl", "nsfwvid",
    # ── AI NSFW / deepfake ───────────────────────────────────────────────
    "deepnude", "nudify", "undress", "clothoff", "nudefab",
    "deepfake", "faceswap", "soulgen", "porngen",
    "aiporn", "ainude", "ainaked",
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


# Keywords safe for iptables SNI string matching.
# Must be long enough to avoid false positives in raw packet data.
# Short words like "ero", "fap", "jav" are excluded — they could match
# inside normal words ("heroine", "japan").
_SNI_SAFE_MIN_LEN = 4

# Keywords shorter than _SNI_SAFE_MIN_LEN that are safe for SNI matching
# because they are unambiguous adult terms unlikely to appear in normal domains.
_SNI_SHORT_EXCEPTIONS = frozenset({"xxx"})


def get_sni_keywords() -> list[str]:
    """Return domain keywords suitable for iptables SNI string matching.

    Filters out keywords shorter than 4 chars to avoid false positives,
    except for explicitly allowed short keywords like 'xxx'.
    """
    return sorted(
        kw for kw in _DOMAIN_KEYWORDS
        if len(kw) >= _SNI_SAFE_MIN_LEN or kw in _SNI_SHORT_EXCEPTIONS
    )


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
