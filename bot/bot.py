#!/usr/bin/env python3
"""
Discord bot for Plural Proxy — Alters Dashboard.

Features:
  /link <code>   — Link your Discord account to the site
  /unlink        — Unlink your Discord account
  /alter         — Select who's fronting (dropdown)
  /fronting      — Show who's currently fronting
  /proxy         — Enable / disable / configure trigger proxy & autoproxy
  /status        — Show connection + proxy status
  /journal       — Write a journal entry (tagged to current fronter)
  /entries       — View recent journal entries

Proxy mode:
  - Proxy (trigger-based): when enabled, messages matching a prefix/suffix
    (e.g. "z: hello") get deleted and re-sent via webhook as the alter.
  - Autoproxy: when enabled AND no trigger matches, every message is
    proxied as the primary (highest) fronting alter.

Setup:
  1. pip install -r requirements.txt
  2. Set DISCORD_BOT_TOKEN in /var/www/plural-proxy/.env
  3. python3 bot.py
"""

import asyncio
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

# ---------------------------------------------------------------------------
#  Project paths — import the shared db module (lives in bot/ alongside this file)
# ---------------------------------------------------------------------------
BOT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BOT_DIR.parent

import db  # noqa: E402  — shared database + encryption module (bot/db.py)

# Site base URL (for avatar images)
SITE_URL = os.environ.get(
    "SITE_URL", "https://pluralproxy.forcequit.xyz"
)

# ---------------------------------------------------------------------------
#  Bot setup
# ---------------------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True  # needed for proxy message detection

bot = commands.Bot(command_prefix="!", intents=intents)

# Accent colour for embeds (matches the site's --accent)
ACCENT = discord.Colour.from_str("#6d9fff")
SUCCESS = discord.Colour.from_str("#34d399")
ERROR = discord.Colour.from_str("#f87171")
WARN = discord.Colour.from_str("#fbbf24")

# Cache webhooks per channel to avoid repeated lookups
_webhook_cache: dict[int, discord.Webhook] = {}


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def alter_name(alter: dict) -> str:
    """Extract the display name from an alter dict."""
    return db.extract_alter_name(alter)


IMAGES_DIR = PROJECT_DIR / "assets" / "images"

def alter_avatar_url(alter: dict) -> str | None:
    """Return the full URL to the alter's profile image, or None.

    Checks the local filesystem first to verify the file actually exists.
    Discord's servers must be able to fetch the URL to display the avatar.
    """
    img = alter.get("image")
    uuid = alter.get("UUID", "")

    # 1. If the alter JSON has an explicit image path, use it
    if img and img not in ("none", "null", ""):
        if img.startswith("http"):
            print(f"[avatar] alter={uuid} using external URL: {img}", flush=True)
            return img

        # Relative path like "assets/images/{uuid}.png"
        local = PROJECT_DIR / img
        if local.is_file():
            url = f"{SITE_URL}/{img.lstrip('/')}"
            print(f"[avatar] alter={uuid} file exists at {local} -> {url}", flush=True)
            return url
        else:
            print(f"[avatar] alter={uuid} image field='{img}' but file NOT found at {local}", flush=True)

    # 2. Fallback: probe the filesystem for known extensions
    if uuid:
        for ext in ("png", "jpg", "jpeg", "gif"):
            candidate = IMAGES_DIR / f"{uuid}.{ext}"
            if candidate.is_file():
                url = f"{SITE_URL}/assets/images/{uuid}.{ext}"
                print(f"[avatar] alter={uuid} probed file {candidate} -> {url}", flush=True)
                return url
        print(f"[avatar] alter={uuid} no image file found in {IMAGES_DIR}", flush=True)

    return None


def alter_summary_fields(alter: dict) -> list[tuple[str, str]]:
    """Return a short list of (label, value) pairs for embed display."""
    fields = []
    mapping = [
        ("Age", "Age"), ("Gender", "Gender"), ("Pronouns", "Presentation"),
        ("Role", "Role"), ("Sexuality", "Sexuality"),
    ]
    found = set()
    for label, key in mapping:
        if key in found:
            continue
        # Fields live inside group arrays (e.g. "Basic Info": [{"Age": "25"}, ...])
        for group_name in ("Basic Info", "System Info", "Identity"):
            group = alter.get(group_name, [])
            if isinstance(group, list):
                for field in group:
                    if isinstance(field, dict) and key in field:
                        val = str(field[key]).strip()
                        if val:
                            fields.append((label, val))
                            found.add(key)
                            break
    return fields


def make_alter_embed(alter: dict, title: str = "Currently Fronting") -> discord.Embed:
    """Build a nice embed card for an alter."""
    name = alter_name(alter)
    colour = ACCENT
    cc = alter.get("cardColor")
    if cc:
        try:
            colour = discord.Colour.from_str(cc)
        except Exception:
            pass

    embed = discord.Embed(title=title, colour=colour)
    embed.set_author(name=name, icon_url=alter_avatar_url(alter))

    summary = alter_summary_fields(alter)
    if summary:
        embed.description = "  •  ".join(f"**{l}:** {v}" for l, v in summary)

    thumb = alter_avatar_url(alter)
    if thumb:
        embed.set_thumbnail(url=thumb)

    return embed


async def get_webhook(channel: discord.TextChannel) -> discord.Webhook:
    """Get or create a webhook for proxying in this channel."""
    if channel.id in _webhook_cache:
        return _webhook_cache[channel.id]

    # Look for existing bot webhook
    try:
        hooks = await channel.webhooks()
        for h in hooks:
            if h.user and h.user.id == bot.user.id:
                _webhook_cache[channel.id] = h
                return h
    except discord.Forbidden:
        raise

    # Create new one
    hook = await channel.create_webhook(name="Alter Proxy")
    _webhook_cache[channel.id] = hook
    return hook


# ---------------------------------------------------------------------------
#  Events
# ---------------------------------------------------------------------------

@bot.event
async def on_ready():
    print(f"Bot is ready as {bot.user} (ID: {bot.user.id})")
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} slash command(s)")
    except Exception as e:
        print(f"Failed to sync commands: {e}")


@bot.event
async def on_message(message: discord.Message):
    """Proxy handler — prefix/suffix triggers (if proxy on), then autoproxy as fronting alter (if autoproxy on)."""
    if message.author.bot:
        return

    match = db.match_proxy(str(message.author.id), message.content)
    if match is None:
        return

    alter = db.get_alter_info(match["user_id"], match["alter_uuid"])
    if alter is None:
        return

    name = alter_name(alter)
    avatar = alter_avatar_url(alter)
    content = match["content"]

    print(f"[proxy] user={match['user_id']} alter={match['alter_uuid']} "
          f"name={name} avatar={avatar} image_field={alter.get('image')!r}",
          flush=True)

    # Quick reachability check — if Discord can't fetch the URL the avatar is ignored
    if avatar:
        try:
            req = urllib.request.Request(avatar, method="HEAD")
            req.add_header("User-Agent", "DiscordBot")
            resp = urllib.request.urlopen(req, timeout=5)
            ct = resp.headers.get("Content-Type", "")
            print(f"[proxy] avatar HEAD {resp.status} Content-Type={ct}", flush=True)
            if "image" not in ct:
                print(f"[proxy] WARNING: avatar URL did not return image content-type", flush=True)
        except Exception as e:
            print(f"[proxy] WARNING: avatar URL unreachable: {e}", flush=True)
            avatar = None  # don't pass a broken URL

    if not content:
        return  # don't proxy empty messages

    try:
        webhook = await get_webhook(message.channel)
        await webhook.send(
            content=content,
            username=name,
            avatar_url=avatar,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        await message.delete()
    except discord.Forbidden:
        pass  # silently fail if missing permissions
    except Exception as e:
        print(f"Proxy error: {e}", flush=True)


# ---------------------------------------------------------------------------
#  /link  — check status / explain how to link
# ---------------------------------------------------------------------------

@bot.tree.command(name="link", description="Check or set up your Discord ↔ Dashboard link")
async def cmd_link(interaction: discord.Interaction):
    discord_id = str(interaction.user.id)

    # Check if already linked
    existing = db.get_user_by_discord(discord_id)
    if existing:
        embed = discord.Embed(
            title="✓ Already Linked",
            description=(
                "Your Discord is linked to the Alters Dashboard.\n\n"
                "**Commands:**\n"
                "• `/alter` — Set who's fronting\n"
                "• `/proxy` — Set up proxy triggers & autoproxy\n"
                "• `/status` — View your connection status\n"
                "• `/unlink` — Disconnect"
            ),
            colour=SUCCESS,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    embed = discord.Embed(
        title="Link Your Account",
        description=(
            "Linking is automatic via Discord SSO!\n\n"
            "**Steps:**\n"
            "1. Go to the **Alters Dashboard** website\n"
            "2. Sign in using **Discord** (or connect Discord in your account settings)\n"
            "3. Click the **Discord** button in the toolbar\n"
            "4. It will auto-link — that's it!\n\n"
            "Once linked, come back here and try `/alter` or `/proxy`."
        ),
        colour=ACCENT,
    )
    embed.set_footer(text=f"{SITE_URL}")
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------------------
#  /unlink
# ---------------------------------------------------------------------------

@bot.tree.command(name="unlink", description="Unlink your Discord from the Alters Dashboard")
async def cmd_unlink(interaction: discord.Interaction):
    discord_id = str(interaction.user.id)
    user = db.get_user_by_discord(discord_id)

    if user is None:
        embed = discord.Embed(
            title="Not Linked",
            description="Your Discord isn't linked to any account.",
            colour=WARN,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    # Show confirmation
    view = UnlinkConfirmView(user["user_id"])
    embed = discord.Embed(
        title="Unlink Discord?",
        description="This will disconnect your Discord from the Alters Dashboard.\nProxy mode and all proxy settings will be disabled.",
        colour=WARN,
    )
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


class UnlinkConfirmView(discord.ui.View):
    def __init__(self, user_id: str):
        super().__init__(timeout=60)
        self.user_id = user_id

    @discord.ui.button(label="Unlink", style=discord.ButtonStyle.danger, emoji="\U0001f513")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        db.unlink_discord(self.user_id)
        embed = discord.Embed(
            title="Unlinked",
            description="Your Discord has been disconnected.",
            colour=SUCCESS,
        )
        await interaction.response.edit_message(embed=embed, view=None)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(
            embed=discord.Embed(title="Cancelled", colour=ACCENT), view=None
        )


# ---------------------------------------------------------------------------
#  /alter  — select who's fronting (dropdown)
# ---------------------------------------------------------------------------

@bot.tree.command(name="alter", description="Select who's currently fronting")
async def cmd_alter(interaction: discord.Interaction):
    try:
        user = db.get_user_by_discord(str(interaction.user.id))
        if user is None:
            await _not_linked(interaction)
            return

        alters = db.get_all_alters(user["user_id"])
        if not alters:
            embed = discord.Embed(
                title="No Alters",
                description="You don't have any alters on the dashboard yet.\nAdd some on the website first!",
                colour=WARN,
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        # Build select menu (max 25 options)
        view = AlterSelectView(user["user_id"], alters[:25])
        embed = discord.Embed(
            title="Who's Fronting?",
            description="Select one or more alters who are currently fronting.",
            colour=ACCENT,
        )

        # Show current fronting with roles
        current = db.get_fronting(user["user_id"])
        if current:
            lines = []
            for f in current:
                info = db.get_alter_info(user["user_id"], f["alter_uuid"])
                name = alter_name(info) if info else f["alter_uuid"][:8]
                role = f.get("role", "secondary")
                badge = "\u2b50" if role == "primary" else "\u25cb"
                lines.append(f"{badge} {name} ({role})")
            embed.add_field(name="Currently fronting", value="\n".join(lines), inline=False)

        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
    except Exception as e:
        print(f"[/alter] Error: {e}", flush=True)
        try:
            await interaction.response.send_message(
                embed=discord.Embed(title="Error", description=str(e), colour=ERROR),
                ephemeral=True,
            )
        except Exception:
            pass


class AlterSelectView(discord.ui.View):
    def __init__(self, user_id: str, alters: list[dict]):
        super().__init__(timeout=120)
        self.user_id = user_id
        select = AlterSelect(user_id, alters)
        self.add_item(select)

        # Clear button
        clear_btn = discord.ui.Button(
            label="Clear Fronting", style=discord.ButtonStyle.secondary, emoji="\u274c", row=1
        )
        clear_btn.callback = self.clear_fronting
        self.add_item(clear_btn)

    async def clear_fronting(self, interaction: discord.Interaction):
        await interaction.response.defer()
        try:
            db.clear_fronting(self.user_id)
            embed = discord.Embed(
                title="Fronting Cleared",
                description="No one is marked as fronting.",
                colour=ACCENT,
            )
            await interaction.edit_original_response(embed=embed, view=None)
        except Exception as e:
            print(f"[clear fronting] Error: {e}", flush=True)


class AlterSelect(discord.ui.Select):
    def __init__(self, user_id: str, alters: list[dict]):
        self.user_id = user_id
        self._alters = {a.get("UUID", ""): a for a in alters}

        options = []
        for a in alters:
            uuid = a.get("UUID", "")
            name = alter_name(a)
            # Build description from role/age
            desc_parts = []
            fields = alter_summary_fields(a)
            for label, val in fields[:2]:
                desc_parts.append(f"{label}: {val}")
            desc = " • ".join(desc_parts) if desc_parts else None

            options.append(discord.SelectOption(
                label=name[:100],
                value=uuid,
                description=desc[:100] if desc else None,
            ))

        super().__init__(
            placeholder="Choose alter(s)\u2026",
            min_values=1, max_values=min(len(options), 25),
            options=options,
        )

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer()
        try:
            selected = self.values  # list of UUIDs
            # Replace fronting: clear then add each
            # First selected = primary, rest = secondary
            db.clear_fronting(self.user_id)
            names = []
            primary_name = None
            for i, uuid in enumerate(selected):
                role = "primary" if i == 0 else "secondary"
                db.add_fronting(self.user_id, uuid, via="discord", role=role)
                alter = self._alters.get(uuid)
                n = alter_name(alter) if alter else uuid[:8]
                names.append(n)
                if i == 0:
                    primary_name = n

            if len(names) == 1:
                alter = self._alters.get(selected[0])
                if alter:
                    embed = make_alter_embed(alter, title="\u2b50 Now Fronting (Primary)")
                    embed.set_footer(text="Set via Discord")
                else:
                    embed = discord.Embed(title="\u2b50 Now Fronting", description=names[0], colour=SUCCESS)
            else:
                desc_lines = [f"\u2b50 **{primary_name}** (primary)"]
                for n in names[1:]:
                    desc_lines.append(f"\u25cb {n} (secondary)")
                embed = discord.Embed(
                    title="Now Fronting",
                    description="\n".join(desc_lines),
                    colour=SUCCESS,
                )
                embed.set_footer(text=f"{len(names)} alters \u2022 Set via Discord")

            await interaction.edit_original_response(embed=embed, view=None)
        except Exception as e:
            print(f"[alter select] Error: {e}", flush=True)
            try:
                await interaction.edit_original_response(
                    embed=discord.Embed(title="Error", description=str(e), colour=ERROR),
                    view=None,
                )
            except Exception:
                pass


# ---------------------------------------------------------------------------
#  /fronting  — show who's fronting
# ---------------------------------------------------------------------------

@bot.tree.command(name="fronting", description="Show who's currently fronting")
async def cmd_fronting(interaction: discord.Interaction):
    user = db.get_user_by_discord(str(interaction.user.id))
    if user is None:
        await _not_linked(interaction)
        return

    current = db.get_fronting(user["user_id"])
    if not current:
        embed = discord.Embed(
            title="No One Fronting",
            description="No alter is currently marked as fronting.\nUse `/alter` to set one.",
            colour=ACCENT,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    desc_lines = []
    embeds = []
    for f in current:
        alter = db.get_alter_info(user["user_id"], f["alter_uuid"])
        role = f.get("role", "secondary")
        name = alter_name(alter) if alter else f["alter_uuid"][:8]
        badge = "\u2b50" if role == "primary" else "\u25cb"
        desc_lines.append(f"{badge} **{name}** ({role})")
        if alter:
            e = make_alter_embed(alter, title=f"{'⭐ ' if role == 'primary' else ''}{name}")
            embeds.append(e)

    summary = discord.Embed(
        title="Currently Fronting",
        description="\n".join(desc_lines),
        colour=ACCENT,
    )
    await interaction.response.send_message(embeds=[summary] + embeds[:9], ephemeral=True)


# ---------------------------------------------------------------------------
#  /proxy  — enable / disable / setup proxy mode
# ---------------------------------------------------------------------------

@bot.tree.command(name="proxy", description="Manage proxy & autoproxy settings")
async def cmd_proxy(interaction: discord.Interaction):
    user = db.get_user_by_discord(str(interaction.user.id))
    if user is None:
        await _not_linked(interaction)
        return

    proxy_on = user.get("proxy_enabled", False)
    autoproxy_on = user.get("autoproxy_enabled", False)
    view = ProxyMainView(user["user_id"], proxy_on, autoproxy_on)
    embed = _proxy_status_embed(user["user_id"], proxy_on, autoproxy_on)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


def _proxy_status_embed(user_id: str, proxy_enabled: bool, autoproxy_enabled: bool) -> discord.Embed:
    """Build the proxy status embed showing both proxy and autoproxy."""
    proxy_status = "🟢 **On**" if proxy_enabled else "🔴 **Off**"
    auto_status = "🟢 **On**" if autoproxy_enabled else "🔴 **Off**"

    embed = discord.Embed(
        title="Proxy Settings",
        description=(
            f"**Proxy (triggers):** {proxy_status}\n"
            f"**Autoproxy (fronter):** {auto_status}\n\n"
            "**Proxy** — messages matching a prefix/suffix trigger "
            "(like `z: hello`) are re-sent as the linked alter.\n"
            "**Autoproxy** — when no trigger matches, messages are "
            "automatically sent as the primary fronting alter."
        ),
        colour=SUCCESS if (proxy_enabled or autoproxy_enabled) else ACCENT,
    )

    # Show who autoproxy would use
    if autoproxy_enabled:
        primary = db.get_primary_fronting(user_id)
        if primary:
            alter = db.get_alter_info(user_id, primary["alter_uuid"])
            name = alter_name(alter) if alter else "Unknown"
            embed.add_field(
                name="Autoproxy Alter",
                value=f"⭐ **{name}** (primary fronter)",
                inline=False,
            )
        else:
            embed.add_field(
                name="Autoproxy Alter",
                value="⚠️ No one is fronting — autoproxy won't activate until someone is set as primary fronter.",
                inline=False,
            )

    proxies = db.get_proxies(user_id)
    if proxies:
        lines = []
        for p in proxies:
            alter = db.get_alter_info(user_id, p["alter_uuid"])
            name = alter_name(alter) if alter else "Unknown"
            trigger = ""
            if p["prefix"]:
                trigger = f"prefix `{p['prefix']}`"
            if p["suffix"]:
                trigger += (", " if trigger else "") + f"suffix `{p['suffix']}`"
            lines.append(f"**{name}** — {trigger or 'no trigger set'}")
        embed.add_field(name="Proxy Triggers", value="\n".join(lines), inline=False)
    else:
        embed.add_field(
            name="No Proxy Triggers",
            value="Click **Add Trigger** to set up prefix/suffix triggers for your alters.",
            inline=False,
        )

    return embed


class ProxyMainView(discord.ui.View):
    def __init__(self, user_id: str, proxy_enabled: bool, autoproxy_enabled: bool):
        super().__init__(timeout=120)
        self.user_id = user_id
        self.proxy_enabled = proxy_enabled
        self.autoproxy_enabled = autoproxy_enabled

        # ── Row 0: Proxy toggle + Autoproxy toggle ──
        if proxy_enabled:
            proxy_btn = discord.ui.Button(
                label="Proxy: On", style=discord.ButtonStyle.danger, emoji="\U0001f534", row=0
            )
        else:
            proxy_btn = discord.ui.Button(
                label="Proxy: Off", style=discord.ButtonStyle.success, emoji="\U0001f7e2", row=0
            )
        proxy_btn.callback = self.toggle_proxy
        self.add_item(proxy_btn)

        if autoproxy_enabled:
            auto_btn = discord.ui.Button(
                label="Autoproxy: On", style=discord.ButtonStyle.danger, emoji="\U0001f534", row=0
            )
        else:
            auto_btn = discord.ui.Button(
                label="Autoproxy: Off", style=discord.ButtonStyle.success, emoji="\U0001f7e2", row=0
            )
        auto_btn.callback = self.toggle_autoproxy
        self.add_item(auto_btn)

        # ── Row 1: Add / Remove trigger ──
        add_btn = discord.ui.Button(
            label="Add Trigger", style=discord.ButtonStyle.primary, emoji="\u2795", row=1
        )
        add_btn.callback = self.add_proxy
        self.add_item(add_btn)

        remove_btn = discord.ui.Button(
            label="Remove Trigger", style=discord.ButtonStyle.secondary, emoji="\U0001f5d1", row=1
        )
        remove_btn.callback = self.remove_proxy
        self.add_item(remove_btn)

    async def toggle_proxy(self, interaction: discord.Interaction):
        new_state = not self.proxy_enabled
        db.set_proxy_enabled(self.user_id, new_state)
        self.proxy_enabled = new_state

        embed = _proxy_status_embed(self.user_id, new_state, self.autoproxy_enabled)
        view = ProxyMainView(self.user_id, new_state, self.autoproxy_enabled)
        await interaction.response.edit_message(embed=embed, view=view)

    async def toggle_autoproxy(self, interaction: discord.Interaction):
        new_state = not self.autoproxy_enabled
        db.set_autoproxy_enabled(self.user_id, new_state)
        self.autoproxy_enabled = new_state

        embed = _proxy_status_embed(self.user_id, self.proxy_enabled, new_state)
        view = ProxyMainView(self.user_id, self.proxy_enabled, new_state)
        await interaction.response.edit_message(embed=embed, view=view)

    async def add_proxy(self, interaction: discord.Interaction):
        alters = db.get_all_alters(self.user_id)
        if not alters:
            await interaction.response.send_message(
                embed=discord.Embed(title="No Alters", description="Add alters on the website first.", colour=WARN),
                ephemeral=True,
            )
            return

        view = ProxyAlterSelectView(self.user_id, alters[:25])
        embed = discord.Embed(
            title="Add Proxy Trigger",
            description="Select an alter to create a proxy trigger for.",
            colour=ACCENT,
        )
        await interaction.response.edit_message(embed=embed, view=view)

    async def remove_proxy(self, interaction: discord.Interaction):
        proxies = db.get_proxies(self.user_id)
        if not proxies:
            await interaction.response.send_message(
                embed=discord.Embed(title="No Triggers", description="Nothing to remove.", colour=WARN),
                ephemeral=True,
            )
            return

        view = ProxyRemoveView(self.user_id, proxies)
        embed = discord.Embed(
            title="Remove Proxy Trigger",
            description="Select a trigger to remove.",
            colour=ACCENT,
        )
        await interaction.response.edit_message(embed=embed, view=view)


class ProxyAlterSelectView(discord.ui.View):
    """Select an alter, then open a modal for the prefix/suffix."""
    def __init__(self, user_id: str, alters: list[dict]):
        super().__init__(timeout=120)
        self.user_id = user_id

        options = []
        for a in alters:
            uuid = a.get("UUID", "")
            name = alter_name(a)
            options.append(discord.SelectOption(
                label=name[:100], value=uuid,
            ))

        select = discord.ui.Select(
            placeholder="Choose an alter…",
            options=options, min_values=1, max_values=1,
        )
        select.callback = self.on_select
        self.add_item(select)

    async def on_select(self, interaction: discord.Interaction):
        uuid = interaction.data["values"][0]
        modal = ProxySetupModal(self.user_id, uuid)
        await interaction.response.send_modal(modal)


class ProxySetupModal(discord.ui.Modal, title="Set Proxy Trigger"):
    prefix = discord.ui.TextInput(
        label="Prefix (e.g. z: or zion:)",
        placeholder="z:",
        required=False,
        max_length=20,
    )
    suffix = discord.ui.TextInput(
        label="Suffix (e.g. -z or |zion)",
        placeholder="-z",
        required=False,
        max_length=20,
    )

    def __init__(self, user_id: str, alter_uuid: str):
        super().__init__()
        self.user_id = user_id
        self.alter_uuid = alter_uuid

        # Pre-fill with existing values if any
        proxies = db.get_proxies(user_id)
        for p in proxies:
            if p["alter_uuid"] == alter_uuid:
                self.prefix.default = p["prefix"] or ""
                self.suffix.default = p["suffix"] or ""
                break

    async def on_submit(self, interaction: discord.Interaction):
        px = self.prefix.value.strip()
        sx = self.suffix.value.strip()

        if not px and not sx:
            await interaction.response.send_message(
                embed=discord.Embed(
                    title="Need a Trigger",
                    description="Set at least a prefix or suffix.",
                    colour=ERROR,
                ),
                ephemeral=True,
            )
            return

        db.set_proxy(self.user_id, self.alter_uuid, prefix=px, suffix=sx)
        alter = db.get_alter_info(self.user_id, self.alter_uuid)
        name = alter_name(alter) if alter else "Alter"

        parts = []
        if px:
            parts.append(f"prefix `{px}`")
        if sx:
            parts.append(f"suffix `{sx}`")

        embed = discord.Embed(
            title="✓ Proxy Trigger Set",
            description=f"**{name}** → {' and '.join(parts)}\n\n"
                        f"Example: `{px}Hello everyone!{sx}`",
            colour=SUCCESS,
        )
        user = db.get_user(self.user_id)
        view = ProxyMainView(
            self.user_id,
            user.get("proxy_enabled", False) if user else False,
            user.get("autoproxy_enabled", False) if user else False,
        )
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


class ProxyRemoveView(discord.ui.View):
    def __init__(self, user_id: str, proxies: list[dict]):
        super().__init__(timeout=60)
        self.user_id = user_id

        options = []
        for p in proxies:
            alter = db.get_alter_info(user_id, p["alter_uuid"])
            name = alter_name(alter) if alter else p["alter_uuid"][:8]
            trigger = p.get("prefix", "") or p.get("suffix", "") or "—"
            options.append(discord.SelectOption(
                label=name[:100],
                value=p["alter_uuid"],
                description=f"Trigger: {trigger}"[:100],
            ))

        select = discord.ui.Select(
            placeholder="Select proxy to remove…",
            options=options, min_values=1, max_values=1,
        )
        select.callback = self.on_select
        self.add_item(select)

    async def on_select(self, interaction: discord.Interaction):
        uuid = interaction.data["values"][0]
        db.remove_proxy(self.user_id, uuid)

        embed = discord.Embed(title="✓ Proxy Trigger Removed", colour=SUCCESS)
        user = db.get_user(self.user_id)
        view = ProxyMainView(
            self.user_id,
            user.get("proxy_enabled", False) if user else False,
            user.get("autoproxy_enabled", False) if user else False,
        )
        await interaction.response.edit_message(embed=embed, view=view)


# ---------------------------------------------------------------------------
#  /status  — show connection info
# ---------------------------------------------------------------------------

@bot.tree.command(name="status", description="Show your Discord ↔ Dashboard connection status")
async def cmd_status(interaction: discord.Interaction):
    user = db.get_user_by_discord(str(interaction.user.id))
    if user is None:
        await _not_linked(interaction)
        return

    embed = discord.Embed(title="Connection Status", colour=ACCENT)
    embed.add_field(name="Linked", value="✓ Yes", inline=True)
    embed.add_field(
        name="Proxy (triggers)",
        value="🟢 On" if user.get("proxy_enabled") else "🔴 Off",
        inline=True,
    )
    embed.add_field(
        name="Autoproxy (fronter)",
        value="🟢 On" if user.get("autoproxy_enabled") else "🔴 Off",
        inline=True,
    )

    # Proxy trigger count
    proxies = db.get_proxies(user["user_id"])
    embed.add_field(name="Triggers", value=str(len(proxies)), inline=True)

    # Fronting
    fronting = db.get_fronting(user["user_id"])
    if fronting:
        names = []
        for f in fronting:
            alter = db.get_alter_info(user["user_id"], f["alter_uuid"])
            names.append(alter_name(alter) if alter else "?")
        embed.add_field(name="Fronting", value=", ".join(names), inline=False)
    else:
        embed.add_field(name="Fronting", value="No one set", inline=False)

    # Alter count
    alters = db.get_all_alters(user["user_id"])
    embed.set_footer(text=f"{len(alters)} alter(s) on dashboard")

    await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------------------
#  /journal  — create a journal entry from Discord
# ---------------------------------------------------------------------------

async def _alter_autocomplete(
    interaction: discord.Interaction,
    current: str,
) -> list[app_commands.Choice[str]]:
    """Autocomplete callback — returns the user's alters filtered by typed text."""
    user = db.get_user_by_discord(str(interaction.user.id))
    if not user:
        return []

    alters = db.get_all_alters(user["user_id"])
    if not alters:
        return []

    # "System" option for system-wide entries
    choices: list[app_commands.Choice[str]] = []
    if not current or "system".startswith(current.lower()):
        choices.append(app_commands.Choice(name="System (no alter)", value=""))

    # Star the primary fronter so it sorts first
    primary = db.get_primary_fronting(user["user_id"])
    primary_uuid = primary["alter_uuid"] if primary else None

    for a in alters:
        uuid = a.get("UUID", "")
        name = alter_name(a)
        if current and current.lower() not in name.lower():
            continue
        label = f"⭐ {name}" if uuid == primary_uuid else name
        choices.append(app_commands.Choice(name=label[:100], value=uuid))
        if len(choices) >= 25:  # Discord cap
            break

    return choices


@bot.tree.command(name="journal", description="Write a journal entry from Discord")
@app_commands.describe(
    text="The journal entry text",
    alter="Which alter to tag this entry to (defaults to primary fronter)",
    title="Optional title for the entry",
    tags="Optional comma-separated tags (e.g. therapy, mood, daily)",
)
@app_commands.autocomplete(alter=_alter_autocomplete)
async def cmd_journal(
    interaction: discord.Interaction,
    text: str,
    alter: Optional[str] = None,
    title: Optional[str] = None,
    tags: Optional[str] = None,
):
    user = db.get_user_by_discord(str(interaction.user.id))
    if user is None:
        await _not_linked(interaction)
        return

    user_id = user["user_id"]

    # Resolve alter: explicit choice → primary fronter → system-wide
    if alter is not None:
        # User explicitly picked (could be "" for System)
        alter_uuid = alter
    else:
        # Default to primary fronter
        primary = db.get_primary_fronting(user_id)
        alter_uuid = primary["alter_uuid"] if primary else ""

    alter_display = "System"
    if alter_uuid:
        alter_info = db.get_alter_info(user_id, alter_uuid)
        if alter_info:
            alter_display = alter_name(alter_info)

    # Parse tags
    tag_list = []
    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        tag_list = tag_list[:20]  # max 20

    try:
        entry = db.create_journal_entry(
            user_id,
            alter_uuid=alter_uuid,
            title=title or "",
            body=text,
            tags=tag_list,
            via="discord",
        )

        embed = discord.Embed(
            title="📝 Journal Entry Saved",
            colour=SUCCESS,
        )
        if title:
            embed.add_field(name="Title", value=title, inline=False)
        preview = text[:200] + ("…" if len(text) > 200 else "")
        embed.add_field(name="Entry", value=preview, inline=False)
        embed.add_field(name="Alter", value=alter_display, inline=True)
        if tag_list:
            embed.add_field(name="Tags", value=", ".join(tag_list), inline=True)
        embed.set_footer(text="View all entries on the dashboard → Journal tab")

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        embed = discord.Embed(
            title="Failed to Save",
            description=str(e),
            colour=ERROR,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------------------
#  /entries  — view recent journal entries
# ---------------------------------------------------------------------------

@bot.tree.command(name="entries", description="View your recent journal entries")
@app_commands.describe(
    count="Number of entries to show (1-10, default 5)",
)
async def cmd_entries(
    interaction: discord.Interaction,
    count: Optional[int] = 5,
):
    user = db.get_user_by_discord(str(interaction.user.id))
    if user is None:
        await _not_linked(interaction)
        return

    user_id = user["user_id"]
    limit = max(1, min(count or 5, 10))

    entries = db.list_journal_entries(user_id, limit=limit, offset=0)
    total = db.count_journal_entries(user_id)

    if not entries:
        embed = discord.Embed(
            title="📝 Journal",
            description="No journal entries yet.\nUse `/journal` to write your first entry!",
            colour=ACCENT,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    embed = discord.Embed(
        title=f"📝 Journal — {total} total entries",
        colour=ACCENT,
    )

    for e in entries:
        alter_display = "System"
        if e.get("alter_uuid"):
            alter_info = db.get_alter_info(user_id, e["alter_uuid"])
            if alter_info:
                alter_display = alter_name(alter_info)

        # Format entry
        entry_title = e.get("title") or "Untitled"
        body_preview = (e.get("body") or "")[:120]
        if len(e.get("body", "")) > 120:
            body_preview += "…"

        tag_str = ""
        if e.get("tags"):
            tag_str = " · " + ", ".join(e["tags"])

        # Parse timestamp — use Discord's dynamic format for local time
        try:
            from datetime import datetime as dt
            ts = dt.fromisoformat(e["created_at"])
            unix_ts = int(ts.timestamp())
            time_str = f"<t:{unix_ts}:f>"  # Discord renders in user's local timezone
        except Exception:
            time_str = e.get("created_at", "")

        via = " 🌐" if e.get("via") == "site" else " 💬"
        value = f"*{alter_display}* — {time_str}{via}{tag_str}\n{body_preview}" if body_preview else f"*{alter_display}* — {time_str}{via}{tag_str}"

        embed.add_field(
            name=entry_title,
            value=value,
            inline=False,
        )

    embed.set_footer(text="Full journal available on the dashboard")
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------------------
#  Shared helpers
# ---------------------------------------------------------------------------

async def _not_linked(interaction: discord.Interaction):
    """Standard 'not linked' response."""
    embed = discord.Embed(
        title="Not Linked",
        description=(
            "Your Discord isn't linked to the Alters Dashboard yet.\n\n"
            "**To link (automatic via Discord SSO):**\n"
            "1. Go to the Alters Dashboard website\n"
            "2. Sign in using **Discord** (or connect Discord in your account settings)\n"
            "3. Click the **Discord** button in the toolbar\n"
            "4. It will auto-link — done!\n\n"
            "Run `/link` for more details."
        ),
        colour=WARN,
    )
    embed.set_footer(text=f"{SITE_URL}")
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------------------
#  Run
# ---------------------------------------------------------------------------

def main():
    token = os.environ.get("DISCORD_BOT_TOKEN")
    if not token:
        print("ERROR: DISCORD_BOT_TOKEN not set in .env")
        print("Add it to /var/www/plural-proxy/.env:")
        print("  DISCORD_BOT_TOKEN=your_bot_token_here")
        sys.exit(1)

    print("Starting Alters Dashboard Discord bot…")
    bot.run(token)


if __name__ == "__main__":
    main()
