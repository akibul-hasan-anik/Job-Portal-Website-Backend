from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str

class UserBase(BaseModel):
    user_name: str
    mobile_number: str
    email: str
    password: str

class CheckUser(BaseModel):
    user_name: str
    password: str
    
class UserForgetPassword(BaseModel):
    email: str
    password: str

class UserDelete(BaseModel):
    user_name: str

class JobDescription(BaseModel):
    user_name: str
    title: str
    description: str
    company: str
    location: str
    salary: str

class Apply(BaseModel):
    user_name: str
    link: str

class Contact(BaseModel):
    first_name: str
    last_name: str
    email: str
    message: str
