import click
from flask_migrate import Migrate
from app import app, db

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
            admin.set_password(app.config.get('ADMIN_PASSWORD', 'changeme'))
            db.session.add(admin)
            db.session.commit()
            click.echo('Admin user created successfully!')
        else:
            click.echo('Admin user already exists!')

@cli.command()
def init_db():
    """Initialize the database."""
    with app.app_context():
        db.create_all()
        click.echo('Database initialized!')

@cli.command()
@click.option('--host', default='127.0.0.1', help='The interface to bind to.')
@click.option('--port', default=5000, help='The port to bind to.')
def run(host, port):
    """Run the Flask development server with debug mode."""
    app.run(host=host, port=port, debug=True)

if __name__ == '__main__':
    cli() 