# Standard library imports
import os
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import re

# Third-party imports
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler
from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    logout_user,
)
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

# Load environment variables
load_dotenv(override=True)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cms.db'
app.config['SCHEDULER_TIMEZONE'] = 'Europe/Lisbon'

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.api_enabled = True
scheduler.start()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://"
)

# Security headers


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Database Models
template_users = db.Table(
    'template_users',
    db.Column('template_id', db.Integer, db.ForeignKey(
        'email_template.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey(
        'user.id'), primary_key=True)
)


class AdminUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120))  # Single name field
    blacklisted = db.Column(db.Boolean, default=False)
    favorite = db.Column(db.Boolean, default=False)

    @property
    def first_name(self):
        """Get first name from full name."""
        return self.name.split()[0] if self.name else ''

    @property
    def last_name(self):
        """Get last name from full name."""
        parts = self.name.split() if self.name else []
        return ' '.join(parts[1:]) if len(parts) > 1 else ''

    @property
    def full_name(self):
        """Return the full name."""
        return self.name or ''


class SenderEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    smtp_server = db.Column(db.String(120), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    smtp_username = db.Column(db.String(120), nullable=False)
    smtp_password = db.Column(db.String(120), nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    templates = db.relationship('EmailTemplate', backref='sender', lazy=True)

    @property
    def formatted_email(self):
        return f"{self.display_name} <{self.email}>"


class EmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    schedule = db.Column(db.String(50))  # cron expression
    sender_id = db.Column(db.Integer, db.ForeignKey('sender_email.id'))
    users = db.relationship(
        'User',
        secondary=template_users,
        lazy='subquery',
        backref=db.backref('templates', lazy=True)
    )


# Flask-Login callback
@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))


# Email sending function
def format_email_body(body):
    """Helper function to format email body consistently"""
    if not body.strip().startswith('<'):
        # For plain text, wrap in a div with proper styling
        body = f'<div style="white-space: pre-line;">{body}</div>'
    return body


def send_email(template_id):
    with app.app_context():
        print(f"Attempting to send email for template {template_id} at {datetime.now()}")
        template = EmailTemplate.query.get(template_id)
        if not template:
            print(f"Template {template_id} not found!")
            return

        if not template.sender:
            print(f"No sender configured for template {template_id}!")
            return

        users = template.users
        print(f"Found {len(users)} users for template {template_id}")

        for user in users:
            if not user.blacklisted:
                try:
                    msg = MIMEMultipart()
                    msg['From'] = formataddr(
                        (template.sender.display_name, template.sender.email)
                    )
                    msg['To'] = user.email
                    msg['Subject'] = template.subject

                    body = template.body
                    replacements = {
                        '{user.first_name}': user.first_name or '',
                        '{user.last_name}': user.last_name or '',
                        '{user.full_name}': user.full_name,
                        '{user.email}': user.email
                    }

                    for key, value in replacements.items():
                        body = body.replace(key, value)

                    body = format_email_body(body)
                    msg.attach(MIMEText(body, 'html'))

                    with smtplib.SMTP(template.sender.smtp_server, template.sender.smtp_port) as server:
                        server.starttls()
                        server.login(
                            template.sender.smtp_username,
                            template.sender.smtp_password
                        )
                        server.send_message(msg)
                    print(f"Successfully sent email to {user.email}")
                except Exception as e:
                    print(f"Error sending email to {user.email}: {str(e)}")


# Routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Only rate limit the login endpoint
def login():
    if request.method == 'POST':
        admin_password = os.getenv('ADMIN_PASSWORD')
        if request.form['password'] == admin_password:
            session['logged_in'] = True
            session.permanent = True  # Make session persist
            return redirect(url_for('index'))
        flash('Invalid password', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    # Order users by favorite status (favorites first) then alphabetically by name
    users = User.query.order_by(User.favorite.desc(), User.name).all()
    templates = EmailTemplate.query.order_by(EmailTemplate.subject).all()
    senders = SenderEmail.query.order_by(SenderEmail.display_name).all()
    return render_template('index.html', users=users, templates=templates, senders=senders)


# Routes for sender management
@app.route('/sender', methods=['POST'])
@login_required
def add_sender():
    try:
        email = request.form['email']
        display_name = request.form['display_name']
        smtp_server = request.form['smtp_server']
        smtp_port = int(request.form['smtp_port'])
        smtp_username = request.form['smtp_username']
        smtp_password = request.form['smtp_password']
        is_default = bool(request.form.get('is_default', False))

        # If this is set as default, remove default from others
        if is_default:
            SenderEmail.query.filter_by(
                is_default=True).update({'is_default': False})

        sender = SenderEmail(
            email=email,
            display_name=display_name,
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            is_default=is_default
        )
        db.session.add(sender)
        db.session.commit()
        flash('Sender email added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding sender email: {str(e)}', 'error')
        db.session.rollback()
    return redirect(url_for('index'))


@app.route('/sender/<int:id>/delete', methods=['POST'])
@login_required
def delete_sender(id):
    sender = SenderEmail.query.get_or_404(id)
    try:
        if EmailTemplate.query.filter_by(sender_id=id).first():
            flash('Cannot delete sender email that is being used by templates!', 'error')
            return redirect(url_for('index'))

        db.session.delete(sender)
        db.session.commit()
        flash('Sender email deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting sender email: {str(e)}', 'error')
        db.session.rollback()
    return redirect(url_for('index'))


@app.route('/sender/<int:id>/test', methods=['POST'])
@login_required
def test_sender(id):
    sender = SenderEmail.query.get_or_404(id)
    try:
        msg = MIMEMultipart()
        msg['From'] = formataddr((sender.display_name, sender.email))
        msg['To'] = sender.email  # Send test email to self
        msg['Subject'] = 'Test Email'

        body = 'This is a test email to verify sender configuration.'
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(sender.smtp_server, sender.smtp_port) as server:
            server.starttls()
            server.login(sender.smtp_username, sender.smtp_password)
            server.send_message(msg)

        flash('Test email sent successfully!', 'success')
    except Exception as e:
        flash(f'Error sending test email: {str(e)}', 'error')

    return redirect(url_for('index'))


# Routes for template management
@app.route('/template', methods=['POST'])
@login_required
def add_template():
    subject = request.form['subject']
    body = request.form['body']
    schedule = request.form['schedule']
    sender_id = request.form['sender_id']

    # Validate schedule format
    schedule_pattern = re.compile(
        r'^((minute|hour|day|month|day_of_week|week)=[*0-9a-zA-Z,-/]+\s*)+$')
    if not schedule_pattern.match(schedule):
        flash(
            'Invalid schedule format. Please use field=value pairs (e.g., hour=9)', 'error')
        return redirect(url_for('index'))

    try:
        schedule_dict = {}
        for part in schedule.split():
            field, value = part.split('=')
            # Convert day_of_week names to numbers (0-6)
            if field == 'day_of_week':
                days_map = {'sun': '0', 'mon': '1', 'tue': '2', 'wed': '3',
                            'thu': '4', 'fri': '5', 'sat': '6'}
                value = ','.join(
                    days_map.get(day.lower(), day)
                    for day in value.split(',')
                )
            schedule_dict[field] = value

        # Reconstruct the schedule string with converted values
        schedule = ' '.join(f"{k}={v}" for k, v in schedule_dict.items())

        template = EmailTemplate(
            subject=subject, body=body, schedule=schedule, sender_id=sender_id)
        db.session.add(template)
        db.session.commit()

        print(f"Creating job for template {
              template.id} with schedule: {schedule_dict}")
        job_id = f'template_{template.id}'

        # Remove any existing job with this ID
        try:
            scheduler.remove_job(job_id)
            print(f"Removed existing job {job_id}")
        except BaseException:
            pass  # Job might not exist

        scheduler.add_job(
            id=job_id,
            func=send_email,
            trigger='cron',
            args=[template.id],
            **schedule_dict,
            misfire_grace_time=None
        )
        print(f"Successfully added job {job_id}")

        # List all jobs for debugging
        jobs = scheduler.get_jobs()
        print(f"Current jobs: {[job.id for job in jobs]}")

        flash('Template created successfully!', 'success')
    except Exception as e:
        print(f"Error creating template: {str(e)}")
        flash(f'Error creating template: {str(e)}', 'error')
        db.session.rollback()
    return redirect(url_for('index'))


@app.route('/template/<int:id>/delete', methods=['POST'])
@login_required
def delete_template(id):
    template = EmailTemplate.query.get_or_404(id)
    try:
        # Try to remove the scheduled job if it exists
        try:
            scheduler.remove_job(f'template_{template.id}')
            print(f"Removed scheduled job for template {template.id}")
        except Exception as job_error:
            # Job might not exist, which is fine
            print(f"Note: No active job found for template {template.id}")

        # Delete the template from database
        db.session.delete(template)
        db.session.commit()
        flash('Template deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting template from database: {str(e)}")
        flash(f'Error deleting template: {str(e)}', 'error')
        db.session.rollback()
    return redirect(url_for('index'))


@app.route('/template/<int:id>/edit', methods=['POST'])
@login_required
def edit_template(id):
    template = EmailTemplate.query.get_or_404(id)
    try:
        # Store old values in case we need to rollback
        old_subject = template.subject
        old_body = template.body
        old_schedule = template.schedule
        old_sender_id = template.sender_id

        # Update template values
        template.subject = request.form['subject']
        template.body = request.form['body']
        template.sender_id = request.form['sender_id']
        schedule = request.form['schedule']

        # Validate schedule format
        schedule_pattern = re.compile(
            r'^((minute|hour|day|month|day_of_week|week)=[*0-9a-zA-Z,-/]+\s*)+$')
        if not schedule_pattern.match(schedule):
            raise ValueError('Invalid schedule format')

        # Parse and validate the schedule
        schedule_dict = {}
        try:
            for part in schedule.split():
                field, value = part.split('=')
                if field == 'day_of_week':
                    days_map = {'sun': '0', 'mon': '1', 'tue': '2', 'wed': '3',
                                'thu': '4', 'fri': '5', 'sat': '6'}
                    value = ','.join(
                        days_map.get(day.lower(), day)
                        for day in value.split(',')
                    )
                schedule_dict[field] = value
        except Exception as e:
            raise ValueError(f'Error parsing schedule: {str(e)}')

        # Test if the schedule is valid for APScheduler
        try:
            from apscheduler.triggers.cron import CronTrigger
            CronTrigger(**schedule_dict)
        except Exception as e:
            raise ValueError(f'Invalid schedule parameters: {str(e)}')

        # Update the schedule
        template.schedule = ' '.join(
            f"{k}={v}" for k, v in schedule_dict.items())

        # Try to update the database first
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise ValueError(f'Database error: {str(e)}')

        # Now update the scheduler
        try:
            # Remove old job if it exists
            try:
                scheduler.remove_job(f'template_{template.id}')
            except BaseException:
                pass  # Job might not exist

            # Add new job
            scheduler.add_job(
                id=f'template_{template.id}',
                func=send_email,
                trigger='cron',
                args=[template.id],
                **schedule_dict,
                misfire_grace_time=None
            )
        except Exception as e:
            # If scheduler update fails, rollback the database changes
            template.subject = old_subject
            template.body = old_body
            template.schedule = old_schedule
            template.sender_id = old_sender_id
            db.session.commit()
            raise ValueError(f'Scheduler error: {str(e)}')

        flash('Template updated successfully!', 'success')

    except ValueError as e:
        flash(f'Error updating template: {str(e)}', 'error')
        db.session.rollback()
    except Exception as e:
        app.logger.error(f'Unexpected error updating template: {str(e)}')
        flash('An unexpected error occurred while updating the template', 'error')
        db.session.rollback()

    return redirect(url_for('index'))


@app.route('/template/<int:id>/users', methods=['POST'])
@login_required
def update_template_users(id):
    template = EmailTemplate.query.get_or_404(id)
    selected_user_ids = request.form.getlist('users')

    try:
        # Clear existing users and add selected ones
        template.users = User.query.filter(
            User.id.in_(selected_user_ids)).all()
        db.session.commit()
        flash('Template recipients updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating template recipients: {str(e)}', 'error')
        db.session.rollback()

    return redirect(url_for('index'))


# Routes for user management
@app.route('/user', methods=['POST'])
@login_required
def add_user():
    try:
        email = request.form['email']
        name = request.form['name']

        user = User(email=email, name=name)
        db.session.add(user)
        db.session.commit()

        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400


@app.route('/user/<int:id>/edit', methods=['POST'])
@login_required
def edit_user(id):
    try:
        user = User.query.get_or_404(id)
        user.email = request.form['email']
        user.name = request.form['name']

        db.session.commit()

        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400


@app.route('/user/<int:id>/toggle-blacklist', methods=['POST'])
@login_required
def toggle_blacklist(id):
    user = User.query.get_or_404(id)
    user.blacklisted = not user.blacklisted
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/user/<int:id>/delete', methods=['POST'])
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/user/<int:id>/send-email', methods=['POST'])
@login_required
def send_direct_email(id):
    user = User.query.get_or_404(id)
    subject = request.form['subject']
    body = request.form['body']

    try:
        msg = MIMEMultipart()
        default_sender = SenderEmail.query.filter_by(is_default=True).first()
        if not default_sender:
            flash('No default sender configured!', 'error')
            return redirect(url_for('index'))

        msg['From'] = formataddr(
            (default_sender.display_name, default_sender.email))
        msg['To'] = user.email
        msg['Subject'] = subject

        replacements = {
            '{user.first_name}': user.first_name or '',
            '{user.last_name}': user.last_name or '',
            '{user.full_name}': user.full_name,
            '{user.email}': user.email
        }

        for key, value in replacements.items():
            body = body.replace(key, value)

        body = format_email_body(body)
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(default_sender.smtp_server, default_sender.smtp_port) as server:
            server.starttls()
            server.login(default_sender.smtp_username,
                         default_sender.smtp_password)
            server.send_message(msg)

        flash(f'Email sent successfully to {user.email}!', 'success')
    except Exception as e:
        flash(f'Error sending email: {str(e)}', 'error')

    return redirect(url_for('index'))


@app.route('/template/<int:id>/test', methods=['POST'])
@login_required
def test_template(id):
    template = EmailTemplate.query.get_or_404(id)
    try:
        if not template.sender:
            flash('No sender configured for this template!', 'error')
            return redirect(url_for('index'))

        msg = MIMEMultipart()
        msg['From'] = formataddr(
            (template.sender.display_name, template.sender.email))
        msg['To'] = template.sender.email  # Send to the sender's email
        msg['Subject'] = f"[TEST] {template.subject}"

        # Create a test version of the body with sender's info
        body = template.body
        replacements = {
            '{user.first_name}': template.sender.display_name,
            '{user.last_name}': '',
            '{user.full_name}': template.sender.display_name,
            '{user.email}': template.sender.email
        }

        for key, value in replacements.items():
            body = body.replace(key, value)

        # Add test banner
        test_banner = '''
            <div style="background-color: #fff3cd; color: #856404; padding: 15px; margin-bottom: 20px; border: 1px solid #ffeeba; border-radius: 4px;">
                <strong>⚠️ Test Email</strong><br>
                This is a test email from your template. Schedule: {schedule}
            </div>
        '''.format(schedule=template.schedule)

        body = format_email_body(body)
        body = test_banner + body
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(template.sender.smtp_server, template.sender.smtp_port) as server:
            server.starttls()
            server.login(template.sender.smtp_username,
                         template.sender.smtp_password)
            server.send_message(msg)

        flash('Test email sent successfully!', 'success')
    except Exception as e:
        flash(f'Error sending test email: {str(e)}', 'error')

    return redirect(url_for('index'))


@app.route('/senders')
@login_required
def senders():
    senders = SenderEmail.query.all()
    return render_template('senders.html', senders=senders)


@app.route('/send-bulk-email', methods=['POST'])
@login_required
def send_bulk_email():
    try:
        user_ids = request.form.getlist('user_ids')
        subject = request.form['subject']
        body = request.form['body']
        users = User.query.filter(User.id.in_(user_ids)).all()

        if not users:
            flash('No users selected!', 'error')
            return redirect(url_for('index'))

        default_sender = SenderEmail.query.filter_by(is_default=True).first()
        if not default_sender:
            flash('No default sender configured!', 'error')
            return redirect(url_for('index'))

        success_count = 0
        error_count = 0

        for user in users:
            if user.blacklisted:
                continue

            try:
                msg = MIMEMultipart()
                msg['From'] = formataddr(
                    (default_sender.display_name, default_sender.email))
                msg['To'] = user.email
                msg['Subject'] = subject

                # Replace variables in body
                user_body = body
                replacements = {
                    '{user.first_name}': user.first_name or '',
                    '{user.last_name}': user.last_name or '',
                    '{user.full_name}': user.full_name,
                    '{user.email}': user.email
                }

                for key, value in replacements.items():
                    user_body = user_body.replace(key, value)

                user_body = format_email_body(user_body)
                msg.attach(MIMEText(user_body, 'html'))

                with smtplib.SMTP(default_sender.smtp_server, default_sender.smtp_port) as server:
                    server.starttls()
                    server.login(default_sender.smtp_username,
                                 default_sender.smtp_password)
                    server.send_message(msg)
                success_count += 1
            except Exception as e:
                print(f"Error sending email to {user.email}: {str(e)}")
                error_count += 1

        if success_count > 0:
            flash(f'Successfully sent emails to {
                  success_count} users!', 'success')
        if error_count > 0:
            flash(f'Failed to send emails to {error_count} users.', 'error')

    except Exception as e:
        flash(f'Error sending bulk email: {str(e)}', 'error')

    return redirect(url_for('index'))


@app.route('/user/<int:id>/toggle-favorite', methods=['POST'])
@login_required
def toggle_favorite(id):
    try:
        user = User.query.get_or_404(id)
        user.favorite = not user.favorite
        db.session.commit()
        return jsonify({
            'success': True,
            'favorite': user.favorite
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400


# Application entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8000)
