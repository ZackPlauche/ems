"""Update user model

Revision ID: 0a8a4a1eb509
Revises: 
Create Date: 2024-12-13 11:42:35.866415

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0a8a4a1eb509'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('name', sa.String(length=120), nullable=True))
        batch_op.drop_column('last_name')
        batch_op.drop_column('first_name')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('first_name', sa.VARCHAR(length=60), nullable=True))
        batch_op.add_column(sa.Column('last_name', sa.VARCHAR(length=60), nullable=True))
        batch_op.drop_column('name')

    # ### end Alembic commands ###
