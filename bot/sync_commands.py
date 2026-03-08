#!/usr/bin/env python3
"""One-shot script to force-sync slash commands to Discord, then exit."""

import asyncio
import os
import sys
from pathlib import Path

# Import the bot module to get the tree registered
BOT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BOT_DIR.parent

import db  # noqa — loads .env (bot/db.py)

# Now import the bot (registers all commands on the tree)
import bot as bot_module  # noqa

async def main():
    token = os.environ.get("DISCORD_BOT_TOKEN")
    if not token:
        print("ERROR: DISCORD_BOT_TOKEN not set in .env")
        sys.exit(1)

    async with bot_module.bot:
        @bot_module.bot.event
        async def on_ready():
            print(f"Logged in as {bot_module.bot.user}")
            try:
                synced = await bot_module.bot.tree.sync()
                print(f"✓ Force-synced {len(synced)} command(s):")
                for cmd in synced:
                    desc = f" — {cmd.description}" if cmd.description else ""
                    print(f"  /{cmd.name}{desc}")
            except Exception as e:
                print(f"✗ Sync failed: {e}")
            finally:
                await bot_module.bot.close()

        await bot_module.bot.start(token)

try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
