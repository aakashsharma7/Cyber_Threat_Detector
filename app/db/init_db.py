from sqlalchemy.orm import Session
from app.db.base_class import Base
from app.db.session import engine
from app.db.models import User
from app.core.auth import get_password_hash
from app.core.config import settings

def init_db() -> None:
    # Create tables
    Base.metadata.create_all(bind=engine)

def create_first_superuser() -> None:
    db = Session(engine)
    try:
        # Check if superuser exists
        superuser = db.query(User).filter(User.is_superuser == True).first()
        if not superuser:
            # Create superuser
            superuser = User(
                email="admin@example.com",
                hashed_password=get_password_hash("admin123"),  # Change this in production!
                is_superuser=True,
                is_active=True
            )
            db.add(superuser)
            db.commit()
            print("Superuser created successfully!")
        else:
            print("Superuser already exists.")
    except Exception as e:
        print(f"Error creating superuser: {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("Creating database tables...")
    init_db()
    print("Creating first superuser...")
    create_first_superuser()
    print("Database initialization completed!") 