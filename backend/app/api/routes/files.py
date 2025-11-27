import uuid
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.crypto import (
    decrypt_file_bytes,
    decrypt_private_key,
    decrypt_symmetric_key_with_private_key,
    encrypt_file_bytes,
    encrypt_symmetric_key_with_public_key,
    generate_storage_path,
    load_certificate,
    sign_bytes,
    verify_signature,
)
from app.db.session import get_db
from app.models import EncryptedFile, FileShare, User, UserCert, UserKey
from app.schemas import FileOut, FileShareRequest, SharedByMeOut, SharedFileOut

router = APIRouter()


@router.post("", response_model=FileOut, status_code=status.HTTP_201_CREATED)
async def upload_file(
    uploaded_file: UploadFile = File(...),
    sign: bool = True,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_key = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if not user_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Generate keys before uploading files")

    contents = await uploaded_file.read()
    ciphertext, symmetric_key, iv, auth_tag = encrypt_file_bytes(contents)
    encrypted_key = encrypt_symmetric_key_with_public_key(symmetric_key, user_key.public_key_pem)

    signature_bytes = None
    signature_algorithm = None
    if sign:
        private_key = decrypt_private_key(user_key.private_key_encrypted, current_user.password_hash)
        # Sign the stored ciphertext so integrity can be validated without re-encrypting.
        signature_bytes = sign_bytes(private_key, ciphertext)
        signature_algorithm = "RSA-PSS-SHA256"

    file_id = uuid.uuid4()
    storage_path = generate_storage_path()
    Path(storage_path).write_bytes(ciphertext)

    record = EncryptedFile(
        id=file_id,
        owner_id=current_user.id,
        filename=uploaded_file.filename or f"upload-{file_id}",
        storage_path=storage_path,
        encryption_algorithm="AES-256-GCM",
        iv=iv,
        auth_tag=auth_tag,
        encrypted_key=encrypted_key,
        key_encryption_algorithm="RSA-3072-OAEP",
        signature=signature_bytes,
        signature_algorithm=signature_algorithm,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("", response_model=List[FileOut])
def list_files(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    records = (
        db.query(EncryptedFile)
        .filter(EncryptedFile.owner_id == current_user.id)
        .order_by(EncryptedFile.created_at.desc())
        .all()
    )
    return records


@router.post("/{file_id}/share", status_code=status.HTTP_201_CREATED)
def share_file(
    file_id: uuid.UUID,
    payload: FileShareRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = db.get(EncryptedFile, file_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if record.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to share this file")

    target_user = db.query(User).filter(User.username == payload.target_username).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")

    recipient_key = db.query(UserKey).filter(UserKey.user_id == target_user.id).first()
    if not recipient_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target user has no keys generated")

    owner_key = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if not owner_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Owner keys not found")

    owner_private_key = decrypt_private_key(owner_key.private_key_encrypted, current_user.password_hash)
    symmetric_key = decrypt_symmetric_key_with_private_key(record.encrypted_key, owner_private_key)
    encrypted_key_for_recipient = encrypt_symmetric_key_with_public_key(
        symmetric_key, recipient_key.public_key_pem
    )

    share = FileShare(
        file_id=record.id,
        owner_id=current_user.id,
        recipient_id=target_user.id,
        encrypted_key_for_recipient=encrypted_key_for_recipient,
    )
    db.add(share)
    db.commit()
    db.refresh(share)

    return {
        "id": share.id,
        "file_id": share.file_id,
        "recipient_username": target_user.username,
        "created_at": share.created_at,
    }


@router.get("/shared-with-me", response_model=List[SharedFileOut])
def list_shared_with_me(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    shares = (
        db.query(FileShare)
        .join(EncryptedFile, FileShare.file_id == EncryptedFile.id)
        .join(User, FileShare.owner_id == User.id)
        .filter(FileShare.recipient_id == current_user.id)
        .order_by(FileShare.created_at.desc())
        .all()
    )

    return [
        SharedFileOut(
            share_id=share.id,
            file_id=share.file_id,
            filename=share.file.filename,
            owner_username=share.owner.username,
            encryption_algorithm=share.file.encryption_algorithm,
            key_encryption_algorithm=share.file.key_encryption_algorithm,
            has_signature=bool(share.file.signature),
            created_at=share.created_at,
        )
        for share in shares
    ]


@router.get("/{file_id}/download")
def download_file(file_id: uuid.UUID, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.get(EncryptedFile, file_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if record.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to access this file")

    user_key = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if not user_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Generate keys before downloading files")

    ciphertext = Path(record.storage_path).read_bytes()
    private_key = decrypt_private_key(user_key.private_key_encrypted, current_user.password_hash)
    symmetric_key = decrypt_symmetric_key_with_private_key(record.encrypted_key, private_key)
    plaintext = decrypt_file_bytes(ciphertext, symmetric_key, record.iv)

    def iterfile():
        yield plaintext

    headers = {"Content-Disposition": f"attachment; filename=\"{record.filename}\""}
    return StreamingResponse(iterfile(), media_type="application/octet-stream", headers=headers)


@router.get("/{file_id}/verify-signature")
def verify_file_signature(file_id: uuid.UUID, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.get(EncryptedFile, file_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if record.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to access this file")

    if not record.signature:
        return {"signed": False}

    user_cert = db.query(UserCert).filter(UserCert.user_id == current_user.id).first()
    if not user_cert:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User certificate not issued")

    public_key = load_certificate(user_cert.cert_pem).public_key()
    ciphertext = Path(record.storage_path).read_bytes()
    valid = verify_signature(public_key, ciphertext, record.signature)

    if user_cert.revoked:
        return {
            "signed": True,
            "valid": False,
            "algorithm": record.signature_algorithm,
            "cert_revoked": True,
        }

    return {
        "signed": True,
        "valid": valid,
        "algorithm": record.signature_algorithm,
        "cert_revoked": False,
    }


@router.get("/shared/{share_id}/download")
def download_shared_file(share_id: uuid.UUID, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    share = db.get(FileShare, share_id)
    if not share:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shared file not found")

    if share.recipient_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to access this shared file")

    record = share.file
    recipient_key = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if not recipient_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User keys not found")

    recipient_private_key = decrypt_private_key(recipient_key.private_key_encrypted, current_user.password_hash)
    symmetric_key = decrypt_symmetric_key_with_private_key(share.encrypted_key_for_recipient, recipient_private_key)

    ciphertext = Path(record.storage_path).read_bytes()
    plaintext = decrypt_file_bytes(ciphertext, symmetric_key, record.iv)

    def iterfile():
        yield plaintext

    headers = {"Content-Disposition": f'attachment; filename="{record.filename}"'}
    return StreamingResponse(iterfile(), media_type="application/octet-stream", headers=headers)


@router.get("/shared-by-me", response_model=List[SharedByMeOut])
def list_shared_by_me(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    shares = (
        db.query(FileShare)
        .join(EncryptedFile, FileShare.file_id == EncryptedFile.id)
        .join(User, FileShare.recipient_id == User.id)
        .filter(FileShare.owner_id == current_user.id)
        .order_by(FileShare.created_at.desc())
        .all()
    )

    return [
        SharedByMeOut(
            share_id=share.id,
            file_id=share.file_id,
            filename=share.file.filename,
            recipient_username=share.recipient.username,
            encryption_algorithm=share.file.encryption_algorithm,
            key_encryption_algorithm=share.file.key_encryption_algorithm,
            has_signature=bool(share.file.signature),
            created_at=share.created_at,
        )
        for share in shares
    ]


@router.delete("/shared/{share_id}")
def revoke_shared_file(share_id: uuid.UUID, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    share = db.get(FileShare, share_id)
    if not share:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shared file not found")

    if share.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to revoke this share")

    db.delete(share)
    db.commit()
    return {"status": "revoked"}
