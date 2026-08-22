"""Telegram bot loop for logscan (service mode).

Wraps a ``python-telegram-bot`` ``Application`` and exposes a set of
commands for launching analyses and adjusting runtime settings. Every
handler is protected by an allowed-chat whitelist.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from .config import Settings, settings_summary
from .log_parser import parse_file
from .opentip import OpenTIPClient, OpenTIPError
from .report_generator import generate, ReportGeneratorError

logger = logging.getLogger(__name__)


class LogscanBot:
    """Telegram bot wrapper for logscan."""

    def __init__(self, settings: Settings) -> None:
        if not settings.is_bot_configured():
            raise ValueError("Telegram bot token is required for service mode")
        self.settings = settings
        self.application: Optional[Application] = None

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    def _is_chat_allowed(self, update: Update) -> bool:
        """Return True if the originating chat is allowed."""
        if not self.settings.telegram_allowed_chats:
            return True  # Empty whitelist means all chats are allowed.
        chat = update.effective_chat
        return bool(chat and chat.id in self.settings.telegram_allowed_chats)

    def _deny(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Reply with an authorization-denied message."""
        chat = update.effective_chat
        if chat and update.effective_message:
            context.bot.send_message(
                chat_id=chat.id, text="You must be in a whitelist to do this."
            )

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    async def _start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._is_chat_allowed(update):
            self._deny(update, context)
            return
        chat = update.effective_chat
        if not chat or not update.effective_message:
            return
        # TODO make the greeting more user-friendly
        await update.effective_message.reply_text(
            "Hello! I am logscan. Send /analyze <path> to analyze a log file.\n"
            "Commands: /start, /analyze <path>, /set_format csv|json, "
            "/set_report_dir <path>, /status"
        )

    async def _status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._is_chat_allowed(update):
            self._deny(update, context)
            return
        if not update.effective_message:
            return
        await update.effective_message.reply_text(
            f"<pre>{settings_summary(self.settings)}</pre>", parse_mode="HTML"
        )

    async def _analyze(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not self._is_chat_allowed(update):
            self._deny(update, context)
            return
        if not update.effective_message:
            return
        message = update.effective_message

        if not self.settings.is_analysis_configured():
            await message.reply_text(
                "Config error: OPENTIP_API_KEY is missing."
            )
            return

        args = context.args
        if not args:
            await message.reply_text("Usage: /analyze <path_to_log_file>")
            return

        file_path = args[0]
        if not os.path.isfile(file_path):
            await message.reply_text(f"File not found: {file_path}")
            return

        await message.reply_text(f"Analyzing {file_path}, this may take a while...")

        try:
            artefacts = parse_file(
                file_path, include_private_ips=self.settings.include_private_ips
            )
            total = len(artefacts["ips"]) + len(artefacts["hashes"])
            if total == 0:
                await message.reply_text("No IP addresses or hashes found in the log.")
                return

            client = OpenTIPClient(
                api_key=self.settings.opentip_api_key,
                endpoint=self.settings.opentip_endpoint,
                backoff_interval=self.settings.opentip_backoff_interval,
                max_retries=self.settings.opentip_max_retries,
            )
            results = client.analyze(artefacts)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(
                self.settings.report_dir,
                f"logscan_report_{timestamp}.{self.settings.report_format}",
            )
            abs_path = generate(results, self.settings.report_format, output_path)

            summary = _result_summary(results)
            # TODO make it pretty
            await message.reply_text(
                f"Analysis complete: {total} artefact(s) analyzed.\n"
                f"Report: {abs_path}\n\n{summary}"
            )
        except (OpenTIPError, ReportGeneratorError, OSError) as exc:
            logger.exception("Something went wrong")
            await message.reply_text(f"Something went wrong: {exc}")

    async def _set_format(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not self._is_chat_allowed(update):
            self._deny(update, context)
            return
        if not update.effective_message:
            return
        message = update.effective_message
        args = context.args
        if not args or args[0].strip().lower() not in ("csv", "json"):
            await message.reply_text("Usage: /set_format csv|json")
            return
        self.settings.report_format = args[0].strip().lower()
        await message.reply_text(f"Report format set to {self.settings.report_format}.")

    async def _set_report_dir(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not self._is_chat_allowed(update):
            self._deny(update, context)
            return
        if not update.effective_message:
            return
        message = update.effective_message
        args = context.args
        if not args:
            await message.reply_text("Usage: /set_report_dir <path>")
            return
        self.settings.report_dir = args[0]
        await message.reply_text(f"Report directory set to {self.settings.report_dir}.")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Build the application and start polling (blocking)."""
        application = Application.builder().token(self.settings.telegram_token).build()

        application.add_handler(CommandHandler("start", self._start))
        application.add_handler(CommandHandler("analyze", self._analyze))
        application.add_handler(CommandHandler("set_format", self._set_format))
        application.add_handler(CommandHandler("set_report_dir", self._set_report_dir))
        application.add_handler(CommandHandler("status", self._status))

        self.application = application
        logger.info("Starting logscan Telegram bot polling")
        application.run_polling()


def _result_summary(results) -> str:
    """Build a short multi-line summary of analysis results."""
    lines = []
    for record in results[:20]:
        lines.append(f"• {record['artefact']}: {record['result']}")
    if len(results) > 20:
        lines.append(f"… and {len(results) - 20} more.")
    return "\n".join(lines)
