import pytest
from cryptography.fernet import Fernet

from ir_arxiv_ranker.paper_state import load_paper_state, save_paper_state


def test_encrypted_paper_state_round_trips_and_rejects_a_wrong_key(tmp_path, monkeypatch):
    path = tmp_path / "discovered_papers.fernet"
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("PAPER_STATE_KEY", key)
    record = {
        "authors": ["Example Author"],
        "in_pool": True,
        "sent": True,
        "priority_author_matches": ["Example Author"],
    }
    state = {"schema_version": 1, "pooled_papers": {"example": record}}
    save_paper_state(path, state)
    ciphertext = path.read_bytes()
    assert b"Example Author" not in ciphertext
    assert b"in_pool" not in ciphertext
    assert key.encode() not in ciphertext

    restored = load_paper_state(path)["pooled_papers"]["example"]
    assert restored["authors"] == ["Example Author"]
    assert restored["in_pool"] and restored["sent"]
    assert "priority_author_matches" not in restored
    save_paper_state(path, state)
    assert path.read_bytes() == ciphertext

    monkeypatch.delenv("PAPER_STATE_KEY")
    with pytest.raises(ValueError, match="PAPER_STATE_KEY is required"):
        load_paper_state(path)
    monkeypatch.setenv("PAPER_STATE_KEY", Fernet.generate_key().decode())
    with pytest.raises(ValueError, match="Could not authenticate"):
        save_paper_state(path, state)
    assert path.read_bytes() == ciphertext
