from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.crypto import encrypt_private_key, generate_rsa_keypair, serialize_public_key
from app.db.session import get_db
from app.models import UserKey
from app.schemas import KeyStatus, UserKeyOut

router = APIRouter()


@router.get("/me", response_model=KeyStatus)
def get_key_status(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    key = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    return KeyStatus(has_keys=key is not None)


@router.post("/me", response_model=UserKeyOut, status_code=status.HTTP_201_CREATED)
def generate_keys(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Keys already exist for this user")

    private_key, public_key = generate_rsa_keypair()
    encrypted_private = encrypt_private_key(private_key, current_user.password_hash)
    record = UserKey(
        user_id=current_user.id,
        public_key_pem=serialize_public_key(public_key),
        private_key_encrypted=encrypted_private,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
