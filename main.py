import json
from enum import Enum
import secrets
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from typing import Optional, List
from pydantic.networks import HttpUrl
from pydantic.types import constr, conint
from pony.orm import Database, Required, Optional as PonyOptional, db_session
from uuid import uuid4
from celery import Celery
from celery.schedules import crontab
from pathlib import Path

# Constants and Configurations
CONFIG_PATH = Path("config.json")
with CONFIG_PATH.open() as f:
    config = json.load(f)

app = FastAPI()
security = HTTPBasic()
db = Database()
celery_app = Celery(__name__, broker=config['celery_broker'])


# Database Models
class Scan(db.Entity):
    scan_id = Required(str, unique=True)
    host = Required(str)
    common = Required(bool)
    ports = PonyOptional(str)
    exclude = PonyOptional(str)
    resolve = Required(bool)
    timing = PonyOptional(int)
    max_retry = PonyOptional(int)
    cron = Required(str)
    tag = PonyOptional(str)
    scan_type = Required(str)
    ping = Required(bool)
    postback = PonyOptional(str)
    enabled = Required(bool)


class Results(db.Entity):
    scan_id = Required(str)
    tag = PonyOptional(str)
    data = Required(str)


db.bind(provider='sqlite', filename=':memory:', create_db=True)
db.generate_mapping(create_tables=True)


# Enums
class ScanType(Enum):
    TCPSYN = "S"
    TCPCON = "T"
    TCPACT = "A"
    TCPWIN = "W"
    MAIMON = "M"
    UDP = "U"
    TCPNULL = "N"
    TCPFIN = "F"
    TCPXMAS = "X"


# Validator for cron expressions
def validate_cron(cls, value, field):
    allowed_chars = set('0123456789*/,-')
    if not set(value).issubset(allowed_chars):
        raise ValueError(f"Invalid characters in {field.name}: {value}")
    return value

class CronModel(BaseModel):
    minute: Optional[str] = Field(None, validator=validate_cron)
    hour: Optional[str] = Field(None, validator=validate_cron)
    day_of_week: Optional[str] = Field(None, validator=validate_cron)
    day_of_month: Optional[str] = Field(None, validator=validate_cron)
    month_of_year: Optional[str] = Field(None, validator=validate_cron)

class AddScanModel(BaseModel):
    host: List[constr(regex=r'^[a-zA-Z0-9.-]{1,255}$')][:20] = Field(...)
    common: bool = Field(...)
    ports: str = Field(None)
    exclude: Optional[constr(regex=r'^[\d,-]*$')] = Field(None)
    resolve: bool = Field(...)
    timing: Optional[conint(ge=0, le=5)] = Field(None)
    max_retry: Optional[conint(ge=0, le=5)] = Field(None)
    cron: CronModel = Field(...)
    tag: Optional[constr(regex=r'^[a-zA-Z0-9-]*$')] = Field(None)
    scan_type: ScanType = Field(...)
    ping: bool = Field(...)
    postback: Optional[HttpUrl] = Field(None)

class DelScanModel(BaseModel):
    scan_id: str = Field(...)
    tag: Optional[str] = Field(None)

class ResultModel(BaseModel):
    scan_id: str = Field(...)
    tag: Optional[str] = Field(None)
    data: str = Field(...)

# Auth Dependency
def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, config['username'])
    correct_password = secrets.compare_digest(credentials.password, config['password'])
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# Endpoints
@app.post("/add")
def add_scan(scan: AddScanModel, _: str = Depends(get_current_username)):
    scan_id = str(uuid4())
    with db_session:
        Scan(
            scan_id=scan_id,
            host=json.dumps(scan.host),
            common=scan.common,
            ports=scan.ports,
            exclude=scan.exclude,
            resolve=scan.resolve,
            timing=scan.timing,
            max_retry=scan.max_retry,
            cron=json.dumps(scan.cron.dict()),
            tag=scan.tag,
            scan_type=scan.scan_type.value,
            ping=scan.ping,
            postback=scan.postback,
            enabled=True
        )
    celery_app.add_periodic_task(
        crontab(**scan.cron.dict()),
        scan.run(scan_id=scan_id, host=scan.host, common=scan.common, ports=scan.ports, exclude=scan.exclude,
                 resolve=scan.resolve, timing=scan.timing, max_retry=scan.max_retry, tag=scan.tag,
                 scan_type=scan.scan_type.value, ping=scan.ping, postback=scan.postback)
    )
    return {"message": "Scan scheduled successfully", "scan_id": scan_id}


@app.post("/del")
def delete_scan(del_request: DelScanModel, _: str = Depends(get_current_username)):
    with db_session:
        scan = Scan.get(scan_id=del_request.scan_id, tag=del_request.tag)
        if scan:
            scan.enabled = False
        else:
            raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "Scan disabled successfully"}


@app.get("/results/{scan_id}/{tag}")
def get_results(scan_id: str, tag: Optional[str], _: str = Depends(get_current_username)):
    with db_session:
        scan = Scan.get(scan_id=scan_id, tag=tag, enabled=True)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found or not enabled")
        result = Results.get(scan_id=scan_id, tag=tag)
        if not result:
            return {"message": "No results found"}
        return json.loads(result.data)


@app.get("/historic/{scan_id}/{tag}")
def get_historic(scan_id: str, tag: Optional[str], _: str = Depends(get_current_username)):
    with db_session:
        result = Results.get(scan_id=scan_id, tag=tag)
        if not result:
            return {"message": "No results found"}
        return json.loads(result.data)
