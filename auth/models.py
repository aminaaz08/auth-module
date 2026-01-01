# auth/models.py
from pydantic import BaseModel
from pydantic.functional_validators import AfterValidator
from typing import Annotated
import re

def validate_email(email: str) -> str:
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        raise ValueError('Invalid email address')
    return email

EmailStr = Annotated[str, AfterValidator(validate_email)]

class UserCreate(BaseModel):
    email: str

class CodeVerifyRequest(BaseModel):
    email: str
    code: str

    