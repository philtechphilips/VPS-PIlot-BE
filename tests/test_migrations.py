"""Fails if the models and the migrations disagree, e.g. a model was changed
without running `poe makemigration`."""

from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from app.core.database import Base


def _run(connection, revisions, direction: str) -> None:
    with Operations.context(MigrationContext.configure(connection)):
        for revision in revisions:
            getattr(revision.module, direction)()


def test_migrations_match_models():
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    revisions = list(reversed(list(script.walk_revisions())))  # oldest first
    engine = create_engine("sqlite://")

    with engine.begin() as connection:
        _run(connection, revisions, "upgrade")
        diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)
        assert diff == [], f"Models and migrations differ: {diff}"

        _run(connection, reversed(revisions), "downgrade")
        assert inspect(connection).get_table_names() == []
