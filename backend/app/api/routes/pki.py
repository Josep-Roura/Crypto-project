import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.crypto import (
    decrypt_ca_private_key,
    encrypt_ca_private_key,
    generate_issuing_ca,
    generate_self_signed_ca,
    issue_user_certificate,
    load_certificate,
    serialize_certificate,
)
from app.db.session import get_db
from app.models import CACert, UserCert, UserKey

router = APIRouter()


@router.post("/bootstrap")
def bootstrap_pki(db: Session = Depends(get_db)):
    existing = db.query(CACert).count()
    if existing > 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="PKI already initialized")

    root_priv, root_cert = generate_self_signed_ca("Crypto Drive Root CA")
    issuing_priv, issuing_cert = generate_issuing_ca(root_priv, root_cert, "Crypto Drive Issuing CA")

    root_record = CACert(
        id=uuid.uuid4(),
        name="Root CA",
        cert_pem=serialize_certificate(root_cert),
        private_key_encrypted=encrypt_ca_private_key(root_priv),
        is_root=True,
    )
    issuing_record = CACert(
        id=uuid.uuid4(),
        name="Issuing CA",
        cert_pem=serialize_certificate(issuing_cert),
        private_key_encrypted=encrypt_ca_private_key(issuing_priv),
        is_root=False,
        parent_id=root_record.id,
    )

    db.add(root_record)
    db.add(issuing_record)
    db.commit()

    return {
        "root_ca": {"id": str(root_record.id), "name": root_record.name},
        "issuing_ca": {"id": str(issuing_record.id), "name": issuing_record.name},
    }


@router.post("/cert/me")
def issue_cert_for_me(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    user_key = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if not user_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User keypair not found")

    existing_cert = db.query(UserCert).filter(UserCert.user_id == current_user.id).first()
    if existing_cert:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Certificate already issued")

    issuing_ca = db.query(CACert).filter(CACert.is_root.is_(False)).first()
    if not issuing_ca:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Issuing CA not available; bootstrap PKI first")

    issuing_priv = decrypt_ca_private_key(issuing_ca.private_key_encrypted)
    issuing_cert_obj = load_certificate(issuing_ca.cert_pem)
    user_cert = issue_user_certificate(
        issuing_private_key=issuing_priv,
        issuing_cert=issuing_cert_obj,
        user_public_key_pem=user_key.public_key_pem,
        common_name=current_user.username,
    )

    record = UserCert(
        id=uuid.uuid4(),
        user_id=current_user.id,
        user_key_id=user_key.id,
        ca_cert_id=issuing_ca.id,
        cert_pem=serialize_certificate(user_cert),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    root_ca = db.query(CACert).filter(CACert.is_root.is_(True)).first()

    chain = [pem for pem in [root_ca.cert_pem if root_ca else None, issuing_ca.cert_pem] if pem]

    return {"user_cert_pem": record.cert_pem, "chain": chain, "issued_at": record.created_at}


@router.get("/cert/me")
def get_cert_for_me(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.query(UserCert).filter(UserCert.user_id == current_user.id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

    issuing_ca = db.get(CACert, record.ca_cert_id)
    root_ca = db.query(CACert).filter(CACert.is_root.is_(True)).first()

    chain: List[str] = []
    if root_ca:
        chain.append(root_ca.cert_pem)
    if issuing_ca:
        chain.append(issuing_ca.cert_pem)

    return {"user_cert_pem": record.cert_pem, "chain": chain, "revoked": record.revoked}


@router.post("/cert/me/revoke")
def revoke_cert_for_me(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.query(UserCert).filter(UserCert.user_id == current_user.id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

    if record.revoked:
        return {"status": "already_revoked", "revoked": True}

    record.revoked = True
    db.commit()
    db.refresh(record)
    return {"status": "revoked", "revoked": True}
