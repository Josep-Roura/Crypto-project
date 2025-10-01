import os
from dotenv import load_dotenv
load_dotenv()

APP_SECRET = os.getenv("APP_SECRET", "change_this_dev_secret").encode()
DB_PATH = os.getenv("DB_PATH", "cipherlab_dev.db")
FILES_DIR = os.getenv("FILES_DIR", "cipherlab_files")

os.makedirs(FILES_DIR, exist_ok=True)
