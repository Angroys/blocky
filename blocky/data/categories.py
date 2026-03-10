"""
Predefined domain categories for one-click blocking.
Each category has an id, display info, and a list of root domains.
The blocking engine expands each domain into its subdomains automatically.
"""

from pathlib import Path


_adult_hosts_cache: list[str] | None = None


def _load_adult_hosts() -> list[str]:
    """Load adult domains from the external hosts file (cached after first call)."""
    global _adult_hosts_cache
    if _adult_hosts_cache is not None:
        return _adult_hosts_cache
    hosts_file = Path(__file__).parent / "adult_hosts.txt"
    if hosts_file.exists():
        with open(hosts_file) as f:
            _adult_hosts_cache = [
                line for raw in f
                if (line := raw.strip()) and not line[0].isdigit()
            ]
    else:
        _adult_hosts_cache = []
    return _adult_hosts_cache


class _LazyDomainList:
    """List-like wrapper that defers loading adult_hosts.txt until first access."""

    __slots__ = ()

    def __iter__(self):
        return iter(_load_adult_hosts())

    def __len__(self):
        return len(_load_adult_hosts())

    def __contains__(self, item):
        return item in _load_adult_hosts()

    def __getitem__(self, index):
        return _load_adult_hosts()[index]

    def __bool__(self):
        return bool(_load_adult_hosts())

    def __repr__(self):
        return f"<LazyDomainList: {len(self)} domains>"


CATEGORIES: dict[str, dict] = {
    "adult": {
        "name": "Adult Content",
        "description": "Pornographic and adult websites",
        "icon": "dialog-warning-symbolic",
        "color": "red",
        "domains": _LazyDomainList(),
    },
    "gambling": {
        "name": "Gambling",
        "description": "Online casinos, sports betting and poker sites",
        "icon": "applications-games-symbolic",
        "color": "orange",
        "domains": [
            "bet365.com",
            "betway.com",
            "draftkings.com",
            "fanduel.com",
            "pokerstars.com",
            "888casino.com",
            "888poker.com",
            "betfair.com",
            "williamhill.com",
            "ladbrokes.com",
            "coral.co.uk",
            "paddypower.com",
            "paddypower.com",
            "unibet.com",
            "bwin.com",
            "partypoker.com",
            "fulltiltpoker.com",
            "bovada.lv",
            "betonline.ag",
            "mybookie.ag",
            "sportsbetting.ag",
            "draftkings.com",
            "caesars.com",
            "harrahs.com",
            "mgmresorts.com",
            "betmgm.com",
            "pointsbet.com",
            "barstoolsportsbook.com",
            "wynnbet.com",
            "superbook.com",
            "foxbet.com",
            "si.com",
            "theScore.bet",
            "casumo.com",
            "casinoroom.com",
            "rizk.com",
            "mr.green",
            "mrgreen.com",
            "leovegas.com",
            "videoslots.com",
            "betsson.com",
            "nordicbet.com",
            "paf.com",
            "coolbet.com",
        ],
    },
    "social": {
        "name": "Social Media",
        "description": "Social networks and short-form video platforms",
        "icon": "user-available-symbolic",
        "color": "cyan",
        "domains": [
            "facebook.com",
            "instagram.com",
            "twitter.com",
            "x.com",
            "tiktok.com",
            "snapchat.com",
            # "reddit.com",
            # "redd.it",
            "tumblr.com",
            "pinterest.com",
            "linkedin.com",
            "whatsapp.com",
            "telegram.org",
            "t.me",
            "discord.com",
            "discordapp.com",
            "threads.net",
            "mastodon.social",
            "twitch.tv",
            "vk.com",
            "ok.ru",
            "weibo.com",
            "wechat.com",
            "bereal.com",
            "clubhouse.com",
            "bsky.app",
            "bluesky.social",
        ],
    },
    "gaming": {
        "name": "Gaming & Streaming",
        "description": "Game stores, streaming platforms and gaming services",
        "icon": "input-gaming-symbolic",
        "color": "purple",
        "domains": [
            "store.steampowered.com",
            "steampowered.com",
            "steamcommunity.com",
            "twitch.tv",
            "epicgames.com",
            "origin.com",
            "ea.com",
            "battle.net",
            "blizzard.com",
            "riotgames.com",
            "leagueoflegends.com",
            "valorant.com",
            "gog.com",
            "ubisoft.com",
            "ubsoft.com",
            "ubi.com",
            "playstation.com",
            "xbox.com",
            "nintendo.com",
            "gamespot.com",
            "ign.com",
            "kotaku.com",
            "polygon.com",
            "miniclip.com",
            "poki.com",
            "addictinggames.com",
            "kongregate.com",
        ],
    },
    "streaming": {
        "name": "Video Streaming",
        "description": "Video on demand and streaming services",
        "icon": "media-playback-start-symbolic",
        "color": "green",
        "domains": [
            "youtube.com",
            "youtu.be",
            "netflix.com",
            "hulu.com",
            "disneyplus.com",
            "primevideo.com",
            "hbomax.com",
            "max.com",
            "peacocktv.com",
            "paramountplus.com",
            "appletv.apple.com",
            "crunchyroll.com",
            "funimation.com",
            "vimeo.com",
            "dailymotion.com",
            "pluto.tv",
            "tubi.tv",
            "crackle.com",
            "curiositystream.com",
        ],
    },
    "news": {
        "name": "News & Media",
        "description": "News websites and online publications",
        "icon": "emblem-documents-symbolic",
        "color": "cyan",
        "domains": [
            "cnn.com",
            "foxnews.com",
            "bbc.com",
            "bbc.co.uk",
            "theguardian.com",
            "nytimes.com",
            "washingtonpost.com",
            "huffpost.com",
            "buzzfeed.com",
            "dailymail.co.uk",
            "breitbart.com",
            "msnbc.com",
            "nbcnews.com",
            "abcnews.go.com",
            "cbsnews.com",
            "usatoday.com",
            "nypost.com",
            "theatlantic.com",
            "politico.com",
            "vice.com",
        ],
    },
}


def get_category(category_id: str) -> dict | None:
    return CATEGORIES.get(category_id)


def get_all_categories() -> list[tuple[str, dict]]:
    return list(CATEGORIES.items())


CATEGORY_COLORS = {
    "red": ("#ff3366", "rgba(255, 51, 102, 0.15)", "rgba(255, 51, 102, 0.35)"),
    "orange": ("#ff6b35", "rgba(255, 107, 53, 0.15)", "rgba(255, 107, 53, 0.35)"),
    "cyan": ("#00d4ff", "rgba(0, 212, 255, 0.15)", "rgba(0, 212, 255, 0.35)"),
    "purple": ("#9d4edd", "rgba(157, 78, 221, 0.15)", "rgba(157, 78, 221, 0.35)"),
    "green": ("#39ff14", "rgba(57, 255, 20, 0.15)", "rgba(57, 255, 20, 0.35)"),
}
