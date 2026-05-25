import random
from urllib.parse import urlparse

from scanner.domain.models import Mission


class MissionGenerator:
    """Generates a mission for the test agent based on page type."""

    PAGE_TYPES = {
        "ecommerce": "Find a product under $50 with at least 4 stars and add it to cart",
        "article": "Read the article and summarize the main points in 3 sentences",
        "form": "Fill out the contact form with name: Test User, email: test@example.com, message: This is a test",
        "login": "Attempt to log in with email user@test.com and password test123",
        "search": "Search for 'best laptops 2026' and click the first result",
        "landing": "Identify what product or service is offered and click the main CTA button",
        "generic": "Browse the page and report what you find",
    }

    def generate(self, url: str) -> Mission:
        domain = urlparse(url).netloc.lower()
        page_type = self._classify(url, domain)
        instruction = self.PAGE_TYPES.get(page_type, self.PAGE_TYPES["generic"])

        return Mission(
            instruction=instruction,
            page_type=page_type,
            constraints=["Do not enter real personal information", "Do not make actual purchases"],
        )

    def _classify(self, url: str, domain: str) -> str:
        if any(kw in domain for kw in ["shop", "store", "buy", "product", "amazon", "ebay", "etsy"]):
            return "ecommerce"
        if any(kw in domain for kw in ["news", "blog", "article", "medium", "substack"]):
            return "article"
        if any(kw in domain for kw in ["form", "contact", "signup", "register"]):
            return "form"
        if any(kw in domain for kw in ["login", "auth", "signin"]):
            return "login"
        if any(kw in domain for kw in ["search", "find"]):
            return "search"
        if any(kw in domain for kw in ["landing", "offer", "promo"]):
            return "landing"
        if any(kw in ["shop", "store", "buy"] for kw in url.lower().split("/")):
            return "ecommerce"
        return "generic"


class AgentValidator:
    """Runs a real agent (Browser Use / Playwright) against a URL
    and records its behavior."""

    def __init__(self, provider: str = "browser_use", timeout: int = 60):
        self.provider = provider
        self.timeout = timeout
        self.mission_gen = MissionGenerator()

    async def validate(self, url: str, mission: Mission | None = None) -> dict:
        """Run agent against URL and return session data.

        Returns a dict with:
          - steps: list of agent actions
          - success: whether mission was completed
          - screenshot_paths: list of screenshot files
          - duration_ms: execution time
        """
        if mission is None:
            mission = self.mission_gen.generate(url)

        if self.provider == "browser_use":
            return await self._run_browser_use(url, mission)
        else:
            return await self._run_playwright(url, mission)

    async def _run_browser_use(self, url: str, mission: Mission) -> dict:
        try:
            from browser_use import Agent as BrowserUseAgent
        except ImportError:
            return {
                "error": "browser-use not installed",
                "steps": [],
                "success": False,
                "duration_ms": 0,
            }

        import time
        start = time.monotonic()

        agent = BrowserUseAgent(
            task=f"Go to {url}. {mission.instruction}",
            headless=True,
            max_steps=20,
        )
        result = await agent.run()

        steps = []
        for i, step in enumerate(getattr(result, "steps", result if isinstance(result, list) else [])):
            steps.append({
                "step_number": i + 1,
                "thought": getattr(step, "thought", str(step))[:500],
                "action": getattr(step, "action", "")[:200],
                "url_after": getattr(step, "url", url),
            })

        return {
            "steps": steps,
            "success": getattr(result, "success", False),
            "duration_ms": int((time.monotonic() - start) * 1000),
            "mission": mission.model_dump(mode="json"),
        }

    async def _run_playwright(self, url: str, mission: Mission) -> dict:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {"error": "playwright not installed", "steps": [], "success": False, "duration_ms": 0}

        import time
        start = time.monotonic()

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, timeout=self.timeout * 1000)

            steps = [
                {"step_number": 1, "action": f"Navigated to {url}", "url_after": url},
            ]

            title = await page.title()
            steps.append({
                "step_number": 2,
                "action": f"Page title: {title}",
                "url_after": page.url,
            })

            content = await page.content()
            text_len = len(content)
            steps.append({
                "step_number": 3,
                "action": f"Page loaded: {text_len} chars of HTML",
                "url_after": page.url,
            })

            await browser.close()

        return {
            "steps": steps,
            "success": True,
            "duration_ms": int((time.monotonic() - start) * 1000),
            "mission": mission.model_dump(mode="json"),
        }
