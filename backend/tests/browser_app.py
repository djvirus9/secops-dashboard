"""Browser integration fixture. Never packaged in the backend production image.

Serve with uvicorn --app-dir tests browser_app:app against the disposable browser
database. The real routes, worker, migrations and finding writes are exercised;
only the outbound GitHub client is replaced with a synthetic complete snapshot.
"""
import asyncio
from contextlib import asynccontextmanager
import os

from app.main import app
from app.github_sync import client, service

os.environ["GITHUB_SYNC_TOKEN"] = "synthetic-browser-github-token-0000000000000000"


def fetch_fixture(repository, sources):
    if repository != "fixture/browser-repository":
        raise client.GitHubFetchError("No synthetic fixture exists for this repository")
    return [client.RemoteAlert(source=source, number=1, state="open", severity="high",
                               title=f"Synthetic {source} alert", description="Browser fixture; no live GitHub traffic")
            for source in sources]


client.fetch_alerts = fetch_fixture
production_lifespan = app.router.lifespan_context


@asynccontextmanager
async def browser_lifespan(application):
    async with production_lifespan(application):
        stopping = asyncio.Event()

        async def run_worker():
            while not stopping.is_set():
                await asyncio.to_thread(service.process_one)
                try:
                    await asyncio.wait_for(stopping.wait(), timeout=0.1)
                except TimeoutError:
                    pass

        task = asyncio.create_task(run_worker())
        try:
            yield
        finally:
            stopping.set()
            await task


app.router.lifespan_context = browser_lifespan
