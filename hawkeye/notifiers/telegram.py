"""
HawkEye — Notifications Telegram
=================================
Envoie des alertes en temps réel vers un canal Telegram via bot API.
Utile pour une surveillance à distance.
"""

import os
from typing import Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None


class TelegramNotifier:
    """Notificateur Telegram asynchrone.

    Configuration via variables d'environnement :
      HAWKEYE_TELEGRAM_TOKEN : Token du bot (ex: 123456:ABC-DEF1234)
      HAWKEYE_TELEGRAM_CHAT_ID : ID du chat/canal (ex: -1001234567890)
    """

    BASE_URL = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(
        self,
        token: Optional[str] = None,
        chat_id: Optional[str] = None,
    ):
        self.token = token or os.getenv("HAWKEYE_TELEGRAM_TOKEN", "")
        self.chat_id = chat_id or os.getenv("HAWKEYE_TELEGRAM_CHAT_ID", "")
        self._session: Optional[aiohttp.ClientSession] = None
        self._enabled = bool(self.token and self.chat_id)

        if self._enabled and aiohttp is None:
            print(
                "[!] Telegram : 'aiohttp' n'est pas installé. "
                "Faites : pip install aiohttp"
            )
            self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def _assurer_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def envoyer_alerte(
        self,
        titre: str,
        domaine: str,
        ip_source: str,
        type_alerte: str,
        details: str = "",
    ) -> bool:
        """Envoie une alerte formatée vers Telegram.

        Retourne True si l'envoi a réussi, False sinon.
        """
        if not self._enabled:
            return False

        icones = {
            "BLACKLIST": "🚨",
            "DGA": "⚠️",
            "DGA_RAFALE": "📡",
            "TUNNEL_DNS": "🔓",
        }
        icone = icones.get(type_alerte, "🔔")

        message = (
            f"{icone} *HawkEye Alerte*\n"
            f"**Type :** {type_alerte}\n"
            f"**Domaine :** `{domaine}`\n"
            f"**IP source :** `{ip_source}`\n"
        )
        if details:
            message += f"**Détails :** _{details}_\n"
        message += (
            f"\n🕐 {__import__('datetime').datetime.now().strftime('%H:%M:%S')}"
        )

        try:
            session = await self._assurer_session()
            url = self.BASE_URL.format(token=self.token)
            async with session.post(
                url,
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True,
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    print(
                        f"[!] Telegram erreur {resp.status}: "
                        f"{await resp.text()}"
                    )
                    return False
                return True
        except Exception as e:
            print(f"[!] Telegram échec envoi : {e}")
            return False

    async def envoyer_stats(self, stats: dict) -> bool:
        """Envoie un résumé des statistiques."""
        if not self._enabled:
            return False

        message = (
            "📊 *HawkEye — Statistiques*\n"
            f"📦 Total requêtes : {stats['total']}\n"
            f"🚨 Alertes : {stats['alertes']}\n"
            f"🌐 Domaines uniques : {stats['domaines_uniques']}\n"
            f"🖥️ IPs sources : {stats['ips_uniques']}\n"
        )
        if stats.get("stats_alertes"):
            message += "\n*Par type d'alerte :*\n"
            for atype, count in stats["stats_alertes"].items():
                message += f"  • {atype}: {count}\n"

        try:
            session = await self._assurer_session()
            url = self.BASE_URL.format(token=self.token)
            async with session.post(
                url,
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False

    async def fermer(self) -> None:
        """Ferme la session HTTP."""
        if self._session and not self._session.closed:
            await self._session.close()
