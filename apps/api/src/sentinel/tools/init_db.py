"""Initialize the schema through the canonical database module."""
from ..database import init_db

if __name__ == "__main__":
    init_db()
    print("Sentinel database schema initialized")
