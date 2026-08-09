"""baseline: bring any deployment's schema up to the application metadata.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-08

This is the bridge migration: before this revision, schema was created
exclusively by ``backend.database.connection.init_db()`` (``create_all`` +
additive shims). The baseline therefore replays exactly that metadata on an
empty database (idempotent, create-if-missing) so ``alembic upgrade head``
works for brand-new deployments, while pre-existing deployments simply get
``alembic stamp head`` (their schema already matches the models).

After this revision, model changes must ship as real, reviewed migrations:
    venv\\Scripts\\python -m alembic revision --autogenerate -m "<change>"
review the generated file, then ``alembic upgrade head``.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from alembic import op  # noqa: E402

revision = "ac765816b06d"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the full model schema if it is missing (safe on any deployment)."""
    from backend.database.models import Base

    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    """Baseline has nothing to undo: prior deployments predate alembic."""
    pass  # noqa: B010