from __future__ import annotations


import pytest

from logscan.lib.config import Settings
from logscan.lib.telegram_bot import LogscanBot, _result_summary


class FakeMessage:
    def __init__(self) -> None:
        self.replies: list[dict] = []

    async def reply_text(self, text: str, parse_mode: str | None = None) -> None:
        self.replies.append({"text": text, "parse_mode": parse_mode})


class FakeChat:
    def __init__(self, chat_id: int) -> None:
        self.id = chat_id


class FakeUpdate:
    def __init__(self, chat_id: int = 123) -> None:
        self.effective_chat = FakeChat(chat_id)
        self._message = FakeMessage()

    @property
    def effective_message(self) -> FakeMessage:
        return self._message


class FakeBot:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send_message(self, chat_id: int, text: str) -> None:
        self.sent.append({"chat_id": chat_id, "text": text})


class FakeContext:
    def __init__(
        self, args: list[str] | None = None, bot: FakeBot | None = None
    ) -> None:
        self.args = args or []
        self.bot = bot or FakeBot()


def make_bot(**settings_kwargs) -> LogscanBot:
    settings = Settings(
        telegram_token="test-token",
        opentip_api_key=settings_kwargs.pop("opentip_api_key", "test-key"),
        **settings_kwargs,
    )
    return LogscanBot(settings)


class TestConstruction:
    def test_requires_telegram_token(self) -> None:
        with pytest.raises(ValueError, match="token is required"):
            LogscanBot(Settings())


class TestAuthorization:
    def test_empty_whitelist_allows_any_chat(self) -> None:
        bot = make_bot()
        assert bot._is_chat_allowed(FakeUpdate(chat_id=1)) is True

    def test_allowed_chat(self) -> None:
        bot = make_bot(telegram_allowed_chats=[123, 456])
        assert bot._is_chat_allowed(FakeUpdate(chat_id=123)) is True

    def test_disallowed_chat(self) -> None:
        bot = make_bot(telegram_allowed_chats=[123])
        assert bot._is_chat_allowed(FakeUpdate(chat_id=999)) is False

    def test_deny_sends_message(self) -> None:
        bot = make_bot(telegram_allowed_chats=[123])
        update = FakeUpdate(chat_id=999)
        context = FakeContext()
        bot._deny(update, context)
        assert context.bot.sent[0]["text"] == "Access denied: chat is not allowed."
        assert context.bot.sent[0]["chat_id"] == 999


class TestStart:
    async def test_start_greeting(self) -> None:
        bot = make_bot()
        update = FakeUpdate()
        context = FakeContext()
        await bot._start(update, context)
        assert update.effective_message.replies[0]["text"].startswith(
            "Hello! I am logscan"
        )

    async def test_start_denied_for_disallowed_chat(self) -> None:
        bot = make_bot(telegram_allowed_chats=[123])
        update = FakeUpdate(chat_id=999)
        context = FakeContext()
        await bot._start(update, context)
        assert update.effective_message.replies == []
        assert context.bot.sent[0]["text"].startswith("Access denied")


class TestStatus:
    async def test_status_hides_secrets(self) -> None:
        bot = make_bot(opentip_api_key="super-secret")
        update = FakeUpdate()
        context = FakeContext()
        await bot._status(update, context)
        reply = update.effective_message.replies[0]
        assert "super-secret" not in reply["text"]
        assert reply["parse_mode"] == "HTML"


class TestSetFormat:
    async def test_valid_format(self) -> None:
        bot = make_bot()
        update = FakeUpdate()
        context = FakeContext(args=["json"])
        await bot._set_format(update, context)
        assert bot.settings.report_format == "json"
        assert "json" in update.effective_message.replies[0]["text"]

    async def test_invalid_format_shows_usage(self) -> None:
        bot = make_bot()
        update = FakeUpdate()
        context = FakeContext(args=["xml"])
        await bot._set_format(update, context)
        assert bot.settings.report_format == "csv"
        assert "Usage: /set_format" in update.effective_message.replies[0]["text"]

    async def test_no_args_shows_usage(self) -> None:
        bot = make_bot()
        update = FakeUpdate()
        context = FakeContext()
        await bot._set_format(update, context)
        assert "Usage: /set_format" in update.effective_message.replies[0]["text"]


class TestSetReportDir:
    async def test_sets_report_dir(self) -> None:
        bot = make_bot()
        update = FakeUpdate()
        context = FakeContext(args=["/some/dir"])
        await bot._set_report_dir(update, context)
        assert bot.settings.report_dir == "/some/dir"

    async def test_no_args_shows_usage(self) -> None:
        bot = make_bot()
        update = FakeUpdate()
        context = FakeContext()
        await bot._set_report_dir(update, context)
        assert "Usage: /set_report_dir" in update.effective_message.replies[0]["text"]


class TestAnalyze:
    async def test_not_configured(self) -> None:
        bot = make_bot(opentip_api_key="")
        update = FakeUpdate()
        context = FakeContext(args=["/tmp/x.log"])
        await bot._analyze(update, context)
        assert (
            "OPENTIP_API_KEY is missing" in update.effective_message.replies[0]["text"]
        )

    async def test_no_args_shows_usage(self) -> None:
        bot = make_bot()
        update = FakeUpdate()
        context = FakeContext()
        await bot._analyze(update, context)
        assert "Usage: /analyze" in update.effective_message.replies[0]["text"]

    async def test_file_not_found(self) -> None:
        bot = make_bot()
        update = FakeUpdate()
        context = FakeContext(args=["/nonexistent/file.log"])
        await bot._analyze(update, context)
        assert "File not found" in update.effective_message.replies[0]["text"]

    async def test_happy_path(self, monkeypatch, tmp_path) -> None:
        log = tmp_path / "access.log"
        log.write_text("conn 8.8.8.8\nmd5=5d41402abc4b2a76b9719d911017c592\n")
        report_dir = str(tmp_path / "reports")

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def analyze(self, artefacts):
                return [
                    {
                        "artefact": "8.8.8.8",
                        "result": "zone=Green",
                        "date": "2026-01-01T00:00:00+00:00",
                    },
                ]

        monkeypatch.setattr("logscan.lib.telegram_bot.OpenTIPClient", FakeClient)
        bot = make_bot(report_dir=report_dir)
        update = FakeUpdate()
        context = FakeContext(args=[str(log)])
        await bot._analyze(update, context)

        replies = update.effective_message.replies
        assert any("Analyzing" in r["text"] for r in replies)
        assert any("Analysis complete" in r["text"] for r in replies)


class TestResultSummary:
    def test_builds_lines(self) -> None:
        results = [{"artefact": "8.8.8.8", "result": "zone=Green", "date": ""}]
        summary = _result_summary(results)
        assert "8.8.8.8: zone=Green" in summary

    def test_truncates_after_20(self) -> None:
        results = [{"artefact": str(i), "result": "x", "date": ""} for i in range(25)]
        summary = _result_summary(results)
        assert summary.count("\n") == 20
        assert "and 5 more" in summary

    def test_empty(self) -> None:
        assert _result_summary([]) == ""
