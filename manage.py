import click
from flask_migrate import Migrate
from app import app, db
from loguru import logger
import os

# Initialize Flask-Migrate
migrate = Migrate(app, db)


@click.group()
def cli():
    """Management script for the application."""
    pass


@cli.command()
def create_admin():
    """Create the admin user."""
    from app import AdminUser
    with app.app_context():
        if not AdminUser.query.filter_by(username='admin').first():
            admin = AdminUser(username='admin')
            admin_password = os.getenv('ADMIN_PASSWORD')
            if not admin_password:
                logger.warning("ADMIN_PASSWORD not set in environment!")
            password_to_use = admin_password or 'changeme'
            logger.debug(f"Setting admin password: {'[custom]' if admin_password else '[default]'}")
            admin.set_password(password_to_use)
            db.session.add(admin)
            db.session.commit()
            logger.info('Admin user created successfully!')
        else:
            logger.info('Admin user already exists!')


@cli.command()
def init_db():
    """Initialize the database."""
    from flask_migrate import stamp
    with app.app_context():
        # Create tables with current schema
        db.create_all()
        # Mark the specific migration as complete using just the revision ID
        stamp(revision='5e4b20ed2cd3')
        logger.info('Database initialized!')


@cli.command()
@click.option('--host', default='127.0.0.1', help='The interface to bind to.')
@click.option('--port', default=5000, help='The port to bind to.')
def run(host, port):
    """Run the Flask development server with debug mode."""
    app.run(host=host, port=port, debug=True)


if __name__ == '__main__':
    cli()
