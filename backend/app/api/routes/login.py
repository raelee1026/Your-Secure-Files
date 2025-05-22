from datetime import timedelta
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Body
from fastapi import Header
from pydantic import BaseModel

from app import crud
from app.api.deps import CurrentUser, SessionDep, get_current_active_superuser
from app.core import security
from app.core.config import settings
from app.core.security import get_password_hash
from app.models import Message, NewPassword, Token, UserPublic
from app.utils import (
    generate_password_reset_token,
    generate_reset_password_email,
    send_email,
    verify_password_reset_token,
    generate_totp_secret,
    verify_totp_token,
    get_totp_qr_code,
    create_temp_token,
    verify_temp_token
)

class TotpRequiredResponse(BaseModel):
    msg: str
    email: str
    requires_totp_setup: bool
    access_token: Optional[str] = None 
    totp_setup_token: Optional[str] = None 

class TotpSetupResponse(BaseModel):
    qr_code_url: str

router = APIRouter(tags=["login"])


@router.post("/login/access-token")
def login_access_token(
    session: SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> TotpRequiredResponse:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    user = crud.authenticate(
        session=session, email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    #access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    #access_token = security.create_access_token(user.id, expires_delta=access_token_expires)

    if user.totp_secret:
        temp_token = create_temp_token(user.id, scope="totp_verify", expires_minutes=20)
        return TotpRequiredResponse(
            msg="TOTP required",
            email=user.email,
            requires_totp_setup=False,
            access_token=temp_token,
            totp_setup_token=None,
        )
    else:
        temp_token = create_temp_token(user.id, scope="totp_setup", expires_minutes=20)
        return TotpRequiredResponse(
            msg="TOTP setup required",
            email=user.email,
            requires_totp_setup=True,
            access_token=None,
            totp_setup_token=temp_token,
        )

@router.post("/login/test-token", response_model=UserPublic)
def test_token(current_user: CurrentUser) -> Any:
    """
    Test access token
    """
    return current_user


@router.post("/password-recovery/{email}")
def recover_password(email: str, session: SessionDep) -> Message:
    """
    Password Recovery
    """
    user = crud.get_user_by_email(session=session, email=email)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email does not exist in the system.",
        )
    password_reset_token = generate_password_reset_token(email=email)
    email_data = generate_reset_password_email(
        email_to=user.email, email=email, token=password_reset_token
    )
    send_email(
        email_to=user.email,
        subject=email_data.subject,
        html_content=email_data.html_content,
    )
    return Message(message="Password recovery email sent")


@router.post("/reset-password/")
def reset_password(session: SessionDep, body: NewPassword) -> Message:
    """
    Reset password
    """
    email = verify_password_reset_token(token=body.token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = crud.get_user_by_email(session=session, email=email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email does not exist in the system.",
        )
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    hashed_password = get_password_hash(password=body.new_password)
    user.hashed_password = hashed_password
    session.add(user)
    session.commit()
    return Message(message="Password updated successfully")


@router.post(
    "/password-recovery-html-content/{email}",
    dependencies=[Depends(get_current_active_superuser)],
    response_class=HTMLResponse,
)
def recover_password_html_content(email: str, session: SessionDep) -> Any:
    """
    HTML Content for Password Recovery
    """
    user = crud.get_user_by_email(session=session, email=email)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this username does not exist in the system.",
        )
    password_reset_token = generate_password_reset_token(email=email)
    email_data = generate_reset_password_email(
        email_to=user.email, email=email, token=password_reset_token
    )

    return HTMLResponse(
        content=email_data.html_content, headers={"subject:": email_data.subject}
    )

'''@router.post("/login/totp-verify", response_model=Token)
def verify_totp(
    session: SessionDep,
    email: str = Body(...),
    totp_code: str = Body(...),
):
    user = crud.get_user_by_email(session=session, email=email)
    if not user or not user.totp_secret:
        raise HTTPException(status_code=400, detail="Invalid user or TOTP not setup")
    
    if not verify_totp_token(user.totp_secret, totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = security.create_access_token(user.id, expires_delta=access_token_expires)
    return Token(access_token=token)'''

@router.post("/login/totp-verify", response_model=Token)
def verify_totp(
    session: SessionDep,
    email: str = Body(...),
    totp_code: str = Body(...),
    authorization: str = Header(...)
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    temp_token = authorization.removeprefix("Bearer ").strip()
    user_id = verify_temp_token(temp_token, expected_scope="totp_verify")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = crud.get_user_by_email(session=session, email=email)
    if not user or not user.totp_secret or str(user.id) != user_id:
        raise HTTPException(status_code=400, detail="Invalid user or TOTP not setup")

    if not verify_totp_token(user.totp_secret, totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = security.create_access_token(user.id, expires_delta=access_token_expires)
    return Token(access_token=token)

'''@router.post("/login/totp-setup", response_model=TotpSetupResponse)
def totp_setup(current_user: CurrentUser, session: SessionDep) -> TotpSetupResponse:
    """Initialize TOTP for the current user and return QR code URL."""
    if current_user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP already setup")
    totp_secret = generate_totp_secret()
    current_user.totp_secret = totp_secret
    session.add(current_user)
    session.commit()
    qr_code_url = get_totp_qr_code(
        issuer="YourAppName",
        account_name=current_user.email,
        secret=totp_secret
    )
    return TotpSetupResponse(qr_code_url=qr_code_url)'''

@router.post("/login/totp-setup", response_model=TotpSetupResponse)
def totp_setup(
    session: SessionDep, 
    authorization: str = Header(...)          
) -> TotpSetupResponse:
    """
    Initialize TOTP for the current user and return QR code URL.
    Requires a temporary token with scope 'totp_setup'.
    """
    # 解析 token
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    token = authorization.removeprefix("Bearer ").strip()
    user_id = verify_temp_token(token, expected_scope="totp_setup")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired TOTP setup token")

    # 取得用戶
    user = crud.get_user_by_id(session=session, user_id=user_id) 
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP already setup")

    # 設定 TOTP 並產生 QR code
    totp_secret = generate_totp_secret()
    user.totp_secret = totp_secret
    session.add(user)
    session.commit()

    qr_code_url = get_totp_qr_code(
        issuer="YoSpace",
        account_name=user.email,
        secret=totp_secret
    )

    return TotpSetupResponse(qr_code_url=qr_code_url)