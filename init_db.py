from app.db.init_db import init_db, create_first_superuser

if __name__ == "__main__":
    print("Creating database tables...")
    init_db()
    print("Creating first superuser...")
    create_first_superuser()
    print("Database initialization completed!") 