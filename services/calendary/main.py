import asyncio
import logging
from datetime import datetime, timedelta

from calendary.app import Application
from calendary.models import Base, User
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("calendar")

PORT = 8888
FLAG_LIFETIME_SEC = 5 * 60 + 5  # + jitter
POSTGRES = "postgresql+asyncpg://postgres:changeme@postgres:5432"

async def start_app():
    log.info("Connecting to database")

    engine = create_async_engine(POSTGRES)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    log.info("Starting server")

    db_sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    app = Application(db_sessionmaker, log)
    app.listen(PORT)

    log.info(f"Server is running at http://127.0.0.1:{PORT}")

    await asyncio.Event().wait()
    await engine.dispose()


async def delete_old_records():
    engine = create_async_engine(POSTGRES)
    db_sessionmaker = async_sessionmaker(engine)
    while True:
        await asyncio.sleep(FLAG_LIFETIME_SEC)

        try:
            async with db_sessionmaker() as session:
                lifetime_ago = datetime.now() - timedelta(seconds=FLAG_LIFETIME_SEC)
                stmt = delete(User).where(User.register_time < lifetime_ago)
                res = await session.execute(stmt)
                await session.commit()
        except Exception as e:
            logging.error(f"Got error while deleting old records: {e}")
            continue

        logging.info(f"Deleted {res.rowcount} old records")


async def main():
    await asyncio.gather(start_app(), delete_old_records())


if __name__ == "__main__":
    asyncio.run(main())
