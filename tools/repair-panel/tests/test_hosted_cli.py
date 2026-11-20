"""CLI: dry-run standaard, uitvoeren alleen met juiste vingerafdruk."""

from __future__ import annotations

import pytest

from conftest import MemoryProvider
from repair_panel.hosted import cli
from repair_panel.hosted.config import load_config
from repair_panel.hosted.registry import HostedRegistry
from repair_panel.models import DNSRecord
from repair_panel.storage import Customer, CustomerRegistry
from test_hosted import M365, SPF_EXT, ZoneResolver

D = "klant.nl"


@pytest.fixture
def env(monkeypatch):
    CustomerRegistry().save(Customer(domain=D, customer_name="Klant BV", provider="cloudflare",
                                     offer_reference="OF-1", offer_accepted_on="2026-01-02",
                                     access_granted_on="2026-01-03"))
    client = MemoryProvider([DNSRecord("_dmarc", "TXT", "v=DMARC1; p=none")])
    vv = MemoryProvider([])
    resolver = ZoneResolver({D: client, "veiligvandaag.nl": vv}, mx=M365, external_txt=SPF_EXT)
    monkeypatch.setattr(cli, "SystemResolver", lambda: resolver)
    monkeypatch.setattr(cli, "_hosted_provider", lambda cfg, read_only: vv)
    monkeypatch.setattr(cli, "_client_provider", lambda d, read_only: client)
    return client, vv


def test_cli_flow(env, capsys):
    client, vv = env
    assert cli.main(["config", "init", "--zone", "veiligvandaag.nl", "--provider", "cloudflare",
                     "--rua", "dmarc@veiligvandaag.nl"]) == 0
    assert load_config().zone == "veiligvandaag.nl"
    assert cli.main(["enroll", D]) == 0
    assert cli.main(["publish", D]) == 0
    out = capsys.readouterr().out
    assert "Dry-run" in out and not vv.records
    fp = out.rsplit("--confirm ", 1)[1].split()[0]
    assert cli.main(["publish", D, "--apply", "--confirm", "verkeerd"]) == 2
    assert not vv.records
    assert cli.main(["publish", D, "--apply", "--confirm", fp]) == 0
    assert len(vv.records) == 3 and HostedRegistry().get(D).state == "published"
    assert cli.main(["verify", D]) == 0
    assert cli.main(["instructions", D]) == 0
    assert "CNAME" in capsys.readouterr().out
    assert cli.main(["status"]) == 0


def test_cli_apply_requires_confirm(env):
    with pytest.raises(SystemExit):
        cli.main(["publish", D, "--apply"])


def test_cli_errors_are_reported_not_raised(env, capsys):
    assert cli.main(["enroll", D]) == 2          # geen config
    assert "Gestopt" in capsys.readouterr().err
