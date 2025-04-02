from app import app
from models import db, User  # Change Admin to User

with app.app_context():
    if not User.query.filter_by(email='admin123@gmail.com').first():
        admin = User(email='admin123@gmail.com', is_admin=True)  # Set is_admin to True
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists.")