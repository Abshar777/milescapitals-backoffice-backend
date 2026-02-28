from fastapi import (
    FastAPI,
    APIRouter,
    HTTPException,
    Depends,
    Request,
    Response,
    UploadFile,
    File,
    Form,
    BackgroundTasks,
)
from fastapi.security import HTTPBearer
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
from enum import Enum
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import httpx
import base64
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

ROOT_DIR = Path(__file__).resolve().parent
load_dotenv(str(ROOT_DIR / ".env"))

# MongoDB connection
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# JWT Configuration
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Create the main app
app = FastAPI(title="FX Broker Back-Office API")

# Create router with /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer(auto_error=False)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============== MODELS ==============


class UserRole:
    ADMIN = "admin"
    SUB_ADMIN = "sub_admin"
    ACCOUNTANT = "accountant"
    VENDOR = "vendor"


class UserBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    email: str
    name: str
    role: str = UserRole.SUB_ADMIN
    picture: Optional[str] = None
    is_active: bool = True
    created_at: datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: str = UserRole.SUB_ADMIN
    # Exchanger-specific fields (only used when role is 'vendor')
    deposit_commission: Optional[float] = 0.0
    withdrawal_commission: Optional[float] = 0.0


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class ClientStatus:
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUSPENDED = "suspended"


class ClientBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    client_id: str
    first_name: str
    last_name: str
    email: str
    phone: Optional[str] = None
    country: Optional[str] = None
    mt5_number: Optional[str] = None
    crm_customer_id: Optional[str] = None
    kyc_status: str = ClientStatus.PENDING
    kyc_documents: List[str] = []
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ClientCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: Optional[str] = None
    country: Optional[str] = None
    mt5_number: Optional[str] = None
    crm_customer_id: Optional[str] = None
    notes: Optional[str] = None


class ClientUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    country: Optional[str] = None
    mt5_number: Optional[str] = None
    crm_customer_id: Optional[str] = None
    kyc_status: Optional[str] = None
    notes: Optional[str] = None


# Treasury/Bank Account Models
class TreasuryAccountType:
    BANK = "bank"
    CRYPTO_WALLET = "crypto_wallet"
    PAYMENT_GATEWAY = "payment_gateway"
    USDT = "usdt"  # USDT Wallet


class TreasuryAccountStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"


# LP (Liquidity Provider) Models
class LPAccountStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"


class LPTransactionType:
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"


class LPAccountCreate(BaseModel):
    lp_name: str
    account_number: Optional[str] = None
    bank_name: Optional[str] = None
    swift_code: Optional[str] = None
    currency: str = "USD"
    contact_person: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    notes: Optional[str] = None


class LPAccountUpdate(BaseModel):
    lp_name: Optional[str] = None
    account_number: Optional[str] = None
    bank_name: Optional[str] = None
    swift_code: Optional[str] = None
    currency: Optional[str] = None
    contact_person: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None


class LPTransactionCreate(BaseModel):
    amount: float
    currency: str = "USD"
    treasury_account_id: Optional[str] = None  # Source/destination treasury
    reference: Optional[str] = None
    notes: Optional[str] = None


# PSP Models
class PSPStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"


class PSPSettlementStatus:
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class CommissionPaidBy:
    CLIENT = "client"
    BROKER = "broker"


class PSPCreate(BaseModel):
    psp_name: str
    commission_rate: float  # percentage e.g., 2.5 for 2.5%
    reserve_fund_rate: float = 0  # percentage for reserve fund
    holding_days: int = 0  # days PSP holds funds before release
    settlement_days: int = 1  # T+1, T+2, etc.
    settlement_destination_id: str  # Treasury account ID
    min_settlement_amount: float = 0
    gateway_fee: float = 0  # Fixed fee per transaction
    refund_fee: float = 0  # Fee charged when processing refunds
    monthly_minimum_fee: float = 0  # Minimum monthly charge by PSP
    description: Optional[str] = None


class PSPUpdate(BaseModel):
    psp_name: Optional[str] = None
    commission_rate: Optional[float] = None
    reserve_fund_rate: Optional[float] = None
    holding_days: Optional[int] = None
    settlement_days: Optional[int] = None
    settlement_destination_id: Optional[str] = None
    min_settlement_amount: Optional[float] = None
    gateway_fee: Optional[float] = None
    refund_fee: Optional[float] = None
    monthly_minimum_fee: Optional[float] = None
    status: Optional[str] = None
    description: Optional[str] = None


# Vendor Models
class VendorStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"


class VendorSettlementType:
    BANK = "bank"
    CASH = "cash"


class VendorSettlementStatus:
    PENDING = "pending"
    APPROVED = "approved"
    COMPLETED = "completed"
    REJECTED = "rejected"


class VendorCreate(BaseModel):
    vendor_name: str
    email: EmailStr
    password: str
    deposit_commission: float = 0  # percentage for deposits (bank)
    withdrawal_commission: float = 0  # percentage for withdrawals (bank)
    deposit_commission_cash: float = 0  # percentage for deposits (cash)
    withdrawal_commission_cash: float = 0  # percentage for withdrawals (cash)
    description: Optional[str] = None


class VendorUpdate(BaseModel):
    vendor_name: Optional[str] = None
    deposit_commission: Optional[float] = None
    withdrawal_commission: Optional[float] = None
    deposit_commission_cash: Optional[float] = None
    withdrawal_commission_cash: Optional[float] = None
    status: Optional[str] = None
    description: Optional[str] = None


# Income & Expense Models
class IncomeExpenseType:
    INCOME = "income"
    EXPENSE = "expense"


class IncomeCategory:
    COMMISSION = "commission"
    SERVICE_FEE = "service_fee"
    INTEREST = "interest"
    OTHER = "other"


class ExpenseCategory:
    BANK_FEE = "bank_fee"
    TRANSFER_CHARGE = "transfer_charge"
    VENDOR_PAYMENT = "vendor_payment"
    OPERATIONAL = "operational"
    MARKETING = "marketing"
    SOFTWARE = "software"
    OTHER = "other"


class IncomeExpenseCreate(BaseModel):
    entry_type: str  # income or expense
    category: Optional[str] = None
    custom_category: Optional[str] = None
    amount: float
    currency: str = "USD"
    treasury_account_id: Optional[str] = None  # Optional when vendor handles it
    vendor_id: Optional[str] = None  # If linked to an exchanger (money partner)
    vendor_supplier_id: Optional[str] = (
        None  # If linked to a service supplier (rent, utilities)
    )
    client_id: Optional[str] = None  # If linked to a client
    ie_category_id: Optional[str] = None  # Custom account category
    vendor_bank_account_name: Optional[str] = None
    vendor_bank_account_number: Optional[str] = None
    vendor_bank_ifsc: Optional[str] = None
    vendor_bank_branch: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    date: Optional[str] = None  # ISO date string
    transaction_mode: Optional[str] = None  # "bank" or "cash"
    collecting_person_name: Optional[str] = None
    collecting_person_number: Optional[str] = None


class IncomeExpenseUpdate(BaseModel):
    category: Optional[str] = None
    custom_category: Optional[str] = None
    amount: Optional[float] = None
    description: Optional[str] = None
    reference: Optional[str] = None


# Loan Models
class LoanStatus:
    ACTIVE = "active"
    PARTIALLY_PAID = "partially_paid"
    FULLY_PAID = "fully_paid"
    OVERDUE = "overdue"
    PENDING_APPROVAL = "pending_approval"
    WRITTEN_OFF = "written_off"


class LoanType:
    SHORT_TERM = "short_term"  # < 1 year
    LONG_TERM = "long_term"  # > 1 year
    CREDIT_LINE = "credit_line"  # Revolving


class RepaymentMode:
    LUMP_SUM = "lump_sum"
    EMI = "emi"  # Monthly installments
    CUSTOM = "custom"  # Custom schedule


class LoanTransactionType:
    DISBURSEMENT = "disbursement"
    REPAYMENT = "repayment"
    INTEREST_PAYMENT = "interest_payment"
    PENALTY = "penalty"
    SWAP_OUT = "swap_out"  # Transferred to another borrower
    SWAP_IN = "swap_in"  # Received from another borrower
    WRITE_OFF = "write_off"
    REFINANCE = "refinance"


# ============== LOGGING SYSTEM ==============
class LogType(str, Enum):
    ACTIVITY = "activity"
    AUTH = "auth"
    AUDIT = "audit"
    ERROR = "error"


class LogAction(str, Enum):
    # Auth actions
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGE = "password_change"
    # CRUD actions
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    # Transaction actions
    APPROVE = "approve"
    REJECT = "reject"
    UPLOAD = "upload"
    EXPORT = "export"
    # System actions
    SYSTEM_ERROR = "system_error"


async def create_log(
    log_type: str,
    action: str,
    module: str,
    user_id: str = None,
    user_name: str = None,
    user_email: str = None,
    user_role: str = None,
    description: str = None,
    details: dict = None,
    ip_address: str = None,
    user_agent: str = None,
    reference_id: str = None,
    old_value: dict = None,
    new_value: dict = None,
    status: str = "success",
):
    """Create a log entry in the database"""
    try:
        log_entry = {
            "log_id": f"log_{uuid.uuid4().hex[:12]}",
            "log_type": log_type,
            "action": action,
            "module": module,
            "user_id": user_id,
            "user_name": user_name,
            "user_email": user_email,
            "user_role": user_role,
            "description": description,
            "details": details or {},
            "ip_address": ip_address,
            "user_agent": user_agent,
            "reference_id": reference_id,
            "old_value": old_value,
            "new_value": new_value,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await db.system_logs.insert_one(log_entry)
    except Exception as e:
        logger.error(f"Failed to create log: {e}")


async def log_activity(
    request: Request,
    user: dict,
    action: str,
    module: str,
    description: str,
    reference_id: str = None,
    details: dict = None,
):
    """Helper to log activity with request info"""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    await create_log(
        log_type="activity",
        action=action,
        module=module,
        user_id=user.get("user_id"),
        user_name=user.get("name"),
        user_email=user.get("email"),
        user_role=user.get("role"),
        description=description,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        reference_id=reference_id,
    )


async def log_audit(
    request: Request,
    user: dict,
    action: str,
    module: str,
    reference_id: str,
    old_value: dict = None,
    new_value: dict = None,
    description: str = None,
):
    """Helper to log audit trail for financial changes"""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    await create_log(
        log_type="audit",
        action=action,
        module=module,
        user_id=user.get("user_id"),
        user_name=user.get("name"),
        user_email=user.get("email"),
        user_role=user.get("role"),
        description=description,
        ip_address=ip_address,
        user_agent=user_agent,
        reference_id=reference_id,
        old_value=old_value,
        new_value=new_value,
    )


class LoanCreate(BaseModel):
    vendor_id: Optional[str] = None  # Link to vendor (borrower company)
    borrower_name: str
    amount: float
    currency: str = "USD"
    interest_rate: float = 0  # Annual percentage (Simple interest)
    loan_type: str = LoanType.SHORT_TERM
    loan_date: str  # ISO date
    due_date: str  # ISO date
    repayment_mode: str = RepaymentMode.LUMP_SUM
    installment_amount: Optional[float] = None  # For EMI mode
    installment_frequency: Optional[str] = None  # monthly, weekly, etc.
    num_installments: Optional[int] = None  # Number of EMIs
    treasury_account_id: str  # Source treasury account
    collateral: Optional[str] = None  # Security/collateral description
    notes: Optional[str] = None


class LoanUpdate(BaseModel):
    borrower_name: Optional[str] = None
    interest_rate: Optional[float] = None
    loan_type: Optional[str] = None
    due_date: Optional[str] = None
    repayment_mode: Optional[str] = None
    installment_amount: Optional[float] = None
    installment_frequency: Optional[str] = None
    num_installments: Optional[int] = None
    collateral: Optional[str] = None
    notes: Optional[str] = None


class LoanRepaymentCreate(BaseModel):
    amount: float
    currency: str = "USD"
    treasury_account_id: str  # Where repayment goes
    payment_date: Optional[str] = None
    reference: Optional[str] = None
    notes: Optional[str] = None
    include_interest: bool = False  # If true, part of payment goes to interest
    exchange_rate: Optional[float] = (
        None  # Custom exchange rate (payment currency -> loan currency)
    )
    amount_in_loan_currency: Optional[float] = (
        None  # Pre-calculated equivalent in loan currency
    )


class LoanSwapRequest(BaseModel):
    target_vendor_id: Optional[str] = None  # New borrower vendor
    target_borrower_name: str  # New borrower name
    reason: Optional[str] = None
    adjust_terms: bool = False  # If true, allows term changes
    new_interest_rate: Optional[float] = None
    new_due_date: Optional[str] = None


# ============== VENDOR SUPPLIER MODELS (Service Suppliers - Rent, Utilities, etc.) ==============
class VendorSupplierStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"


class VendorSupplierCreate(BaseModel):
    name: str
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    # Bank details
    bank_name: Optional[str] = None
    bank_account_name: Optional[str] = None
    bank_account_number: Optional[str] = None
    bank_ifsc: Optional[str] = None
    bank_branch: Optional[str] = None
    notes: Optional[str] = None


class VendorSupplierUpdate(BaseModel):
    name: Optional[str] = None
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    bank_name: Optional[str] = None
    bank_account_name: Optional[str] = None
    bank_account_number: Optional[str] = None
    bank_ifsc: Optional[str] = None
    bank_branch: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None


# ============== IE CATEGORY MODELS (Account Categories) ==============
class IECategoryType:
    INCOME = "income"
    EXPENSE = "expense"
    BOTH = "both"  # Can be used for both income and expense


class IECategoryCreate(BaseModel):
    name: str
    category_type: str = IECategoryType.BOTH  # income, expense, or both
    description: Optional[str] = None
    parent_category_id: Optional[str] = None  # For subcategories


class IECategoryUpdate(BaseModel):
    name: Optional[str] = None
    category_type: Optional[str] = None
    description: Optional[str] = None
    parent_category_id: Optional[str] = None
    is_active: Optional[bool] = None


# ============== LIVE FX RATE SERVICE ==============
FALLBACK_RATES_TO_USD = {
    "USD": 1.0,
    "EUR": 1.08,
    "GBP": 1.27,
    "AED": 0.27,
    "SAR": 0.27,
    "INR": 0.012,
    "JPY": 0.0067,
    "USDT": 1.0,
}

_fx_cache = {"rates": None, "fetched_at": None, "source": "fallback"}
FX_CACHE_TTL = timedelta(hours=1)


async def fetch_live_rates() -> dict:
    """Fetch live rates from open.er-api.com (USD base). Returns {currency: rate_to_usd}."""
    try:
        async with httpx.AsyncClient(timeout=10) as client_http:
            resp = await client_http.get("https://open.er-api.com/v6/latest/USD")
            resp.raise_for_status()
            data = resp.json()
            if data.get("result") != "success":
                raise ValueError("API returned non-success result")
            raw = data["rates"]  # e.g. {"USD":1, "AED":3.6725, ...}
            # Convert to "rate_to_usd" format: 1 unit of currency = X USD
            rates_to_usd = {}
            for code, val in raw.items():
                rates_to_usd[code] = round(1.0 / val, 8) if val else 0
            return rates_to_usd
    except Exception as e:
        logger.warning(f"Live FX fetch failed: {e}")
        return None


async def get_fx_rates() -> dict:
    """Return cached rates dict {currency: rate_to_usd}. Refreshes if stale."""
    now = datetime.now(timezone.utc)
    if (
        _fx_cache["rates"]
        and _fx_cache["fetched_at"]
        and (now - _fx_cache["fetched_at"]) < FX_CACHE_TTL
    ):
        return _fx_cache["rates"]
    live = await fetch_live_rates()
    if live:
        _fx_cache["rates"] = live
        _fx_cache["fetched_at"] = now
        _fx_cache["source"] = "live"
        return live
    if _fx_cache["rates"]:
        return _fx_cache["rates"]
    _fx_cache["rates"] = FALLBACK_RATES_TO_USD
    _fx_cache["source"] = "fallback"
    return FALLBACK_RATES_TO_USD


def convert_to_usd(amount: float, currency: str) -> float:
    """Sync wrapper – uses whatever is in cache (or fallback)."""
    rates = _fx_cache.get("rates") or FALLBACK_RATES_TO_USD
    rate = rates.get(currency.upper(), 1.0)
    return round(amount * rate, 2)


def convert_from_usd(amount: float, target_currency: str) -> float:
    """Convert USD amount to target currency."""
    rates = _fx_cache.get("rates") or FALLBACK_RATES_TO_USD
    rate = rates.get(target_currency.upper(), 1.0)
    if rate == 0:
        return amount
    return round(amount / rate, 2)


def convert_currency(amount: float, from_currency: str, to_currency: str) -> float:
    """Convert amount between any two currencies via USD as intermediate."""
    if from_currency.upper() == to_currency.upper():
        return amount
    usd_amount = convert_to_usd(amount, from_currency)
    return convert_from_usd(usd_amount, to_currency)


class TreasuryAccountCreate(BaseModel):
    account_name: str
    account_type: str = TreasuryAccountType.BANK
    bank_name: Optional[str] = None
    account_number: Optional[str] = None
    routing_number: Optional[str] = None
    swift_code: Optional[str] = None
    currency: str = "USD"
    description: Optional[str] = None
    opening_balance: float = 0.0
    # USDT specific fields
    usdt_address: Optional[str] = None
    usdt_network: Optional[str] = None  # TRC20, ERC20, BEP20
    usdt_notes: Optional[str] = None


class TreasuryAccountUpdate(BaseModel):
    account_name: Optional[str] = None
    bank_name: Optional[str] = None
    account_number: Optional[str] = None
    routing_number: Optional[str] = None
    swift_code: Optional[str] = None
    currency: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    # USDT specific fields
    usdt_address: Optional[str] = None
    usdt_network: Optional[str] = None
    usdt_notes: Optional[str] = None


class TransactionType:
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    TRANSFER = "transfer"
    COMMISSION = "commission"
    REBATE = "rebate"
    ADJUSTMENT = "adjustment"


class TransactionStatus:
    PENDING = "pending"
    APPROVED = "approved"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    FAILED = "failed"


class TransactionCreate(BaseModel):
    client_id: str
    transaction_type: str
    amount: float
    currency: str = "USD"
    base_currency: str = "USD"
    base_amount: Optional[float] = None
    destination_type: str = "treasury"  # "treasury", "psp", "vendor", "bank", "usdt"
    destination_account_id: Optional[str] = None
    psp_id: Optional[str] = None
    vendor_id: Optional[str] = None
    commission_paid_by: Optional[str] = None  # "client" or "broker"
    description: Optional[str] = None
    reference: Optional[str] = None
    transaction_mode: Optional[str] = None  # "bank" or "cash"
    collecting_person_name: Optional[str] = None
    collecting_person_number: Optional[str] = None
    # Client bank details (for withdrawal to bank)
    client_bank_name: Optional[str] = None
    client_bank_account_name: Optional[str] = None
    client_bank_account_number: Optional[str] = None
    client_bank_swift_iban: Optional[str] = None
    client_bank_currency: Optional[str] = None
    # Client USDT details (for withdrawal to USDT)
    client_usdt_address: Optional[str] = None
    client_usdt_network: Optional[str] = None  # TRC20, ERC20, BEP20


class TransactionUpdate(BaseModel):
    status: Optional[str] = None
    description: Optional[str] = None
    rejection_reason: Optional[str] = None


# ============== HELPER FUNCTIONS ==============


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_jwt_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(request: Request) -> dict:
    # Check cookie first
    session_token = request.cookies.get("session_token")
    if session_token:
        session = await db.user_sessions.find_one(
            {"session_token": session_token}, {"_id": 0}
        )
        if session:
            expires_at = session.get("expires_at")
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at > datetime.now(timezone.utc):
                user = await db.users.find_one(
                    {"user_id": session["user_id"]}, {"_id": 0}
                )
                if user:
                    return user

    # Check Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        # Check if it's a session token
        session = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
        if session:
            expires_at = session.get("expires_at")
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at > datetime.now(timezone.utc):
                user = await db.users.find_one(
                    {"user_id": session["user_id"]}, {"_id": 0}
                )
                if user:
                    return user

        # Try JWT token
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user = await db.users.find_one({"user_id": payload["user_id"]}, {"_id": 0})
            if user:
                return user
        except jwt.ExpiredSignatureError:
            pass
        except jwt.InvalidTokenError:
            pass

    raise HTTPException(status_code=401, detail="Not authenticated")


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def require_accountant_or_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") not in [UserRole.ADMIN, UserRole.ACCOUNTANT]:
        raise HTTPException(
            status_code=403, detail="Accountant or Admin access required"
        )
    return user


async def require_vendor(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != UserRole.VENDOR:
        raise HTTPException(status_code=403, detail="Vendor access required")
    return user


async def require_vendor_or_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") not in [UserRole.ADMIN, UserRole.VENDOR]:
        raise HTTPException(status_code=403, detail="Vendor or Admin access required")
    return user


# ============== AUTH ROUTES ==============


@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    existing = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = f"user_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    user_doc = {
        "user_id": user_id,
        "email": user_data.email,
        "password_hash": hash_password(user_data.password),
        "name": user_data.name,
        "role": user_data.role,
        "picture": None,
        "is_active": True,
        "created_at": now.isoformat(),
    }

    await db.users.insert_one(user_doc)

    token = create_jwt_token(user_id, user_data.email, user_data.role)

    return TokenResponse(
        access_token=token,
        user={
            "user_id": user_id,
            "email": user_data.email,
            "name": user_data.name,
            "role": user_data.role,
        },
    )


@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")

    if not user:
        # Log failed login attempt
        await create_log(
            log_type="auth",
            action="login_failed",
            module="authentication",
            user_email=credentials.email,
            description=f"Failed login attempt: User not found",
            ip_address=ip_address,
            user_agent=user_agent,
            status="failed",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(credentials.password, user.get("password_hash", "")):
        # Log failed login attempt
        await create_log(
            log_type="auth",
            action="login_failed",
            module="authentication",
            user_id=user.get("user_id"),
            user_email=credentials.email,
            user_name=user.get("name"),
            description=f"Failed login attempt: Invalid password",
            ip_address=ip_address,
            user_agent=user_agent,
            status="failed",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is disabled")

    token = create_jwt_token(user["user_id"], user["email"], user["role"])

    # Log successful login
    await create_log(
        log_type="auth",
        action="login",
        module="authentication",
        user_id=user["user_id"],
        user_email=user["email"],
        user_name=user["name"],
        user_role=user["role"],
        description=f"User logged in successfully",
        ip_address=ip_address,
        user_agent=user_agent,
        status="success",
    )

    return TokenResponse(
        access_token=token,
        user={
            "user_id": user["user_id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
        },
    )


@api_router.post("/auth/session")
async def process_session(request: Request, response: Response):
    """Process Google OAuth session_id"""
    body = await request.json()
    session_id = body.get("session_id")

    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")

    async with httpx.AsyncClient() as http_client:
        try:
            resp = await http_client.get(
                "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
                headers={"X-Session-ID": session_id},
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid session")

            session_data = resp.json()
        except Exception as e:
            logger.error(f"Auth error: {e}")
            raise HTTPException(status_code=401, detail="Authentication failed")

    email = session_data.get("email")
    name = session_data.get("name")
    picture = session_data.get("picture")
    session_token = session_data.get("session_token")

    now = datetime.now(timezone.utc)

    user = await db.users.find_one({"email": email}, {"_id": 0})

    if user:
        user_id = user["user_id"]
        await db.users.update_one(
            {"email": email}, {"$set": {"name": name, "picture": picture}}
        )
    else:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        user_doc = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "picture": picture,
            "role": UserRole.SUB_ADMIN,
            "is_active": True,
            "created_at": now.isoformat(),
        }
        await db.users.insert_one(user_doc)

    expires_at = now + timedelta(days=7)
    await db.user_sessions.insert_one(
        {
            "user_id": user_id,
            "session_token": session_token,
            "expires_at": expires_at.isoformat(),
            "created_at": now.isoformat(),
        }
    )

    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
        max_age=7 * 24 * 60 * 60,
    )

    user = await db.users.find_one({"user_id": user_id}, {"_id": 0})
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user["name"],
        "role": user.get("role", UserRole.SUB_ADMIN),
        "picture": user.get("picture"),
    }


@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user["name"],
        "role": user.get("role", UserRole.SUB_ADMIN),
        "picture": user.get("picture"),
    }


@api_router.post("/auth/logout")
async def logout(request: Request, response: Response):
    session_token = request.cookies.get("session_token")
    if session_token:
        await db.user_sessions.delete_one({"session_token": session_token})
    response.delete_cookie("session_token", path="/")
    return {"message": "Logged out"}


# ============== USERS/ADMINS ROUTES ==============


@api_router.get("/users")
async def get_users(user: dict = Depends(require_admin)):
    users = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(1000)
    return users


@api_router.post("/users")
async def create_user(user_data: UserCreate, admin: dict = Depends(require_admin)):
    existing = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")

    user_id = f"user_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    user_doc = {
        "user_id": user_id,
        "email": user_data.email,
        "password_hash": hash_password(user_data.password),
        "name": user_data.name,
        "role": user_data.role,
        "picture": None,
        "is_active": True,
        "created_at": now.isoformat(),
    }

    # If role is vendor/exchanger, also create a vendor entity
    if user_data.role == UserRole.VENDOR:
        vendor_id = f"vendor_{uuid.uuid4().hex[:12]}"
        user_doc["vendor_id"] = vendor_id  # Link user to vendor

        vendor_doc = {
            "vendor_id": vendor_id,
            "user_id": user_id,
            "vendor_name": user_data.name,
            "email": user_data.email,
            "deposit_commission": user_data.deposit_commission or 0.0,
            "withdrawal_commission": user_data.withdrawal_commission or 0.0,
            "description": f"Exchanger created via User Management",
            "total_volume": 0.0,
            "total_commission": 0.0,
            "pending_settlement": 0.0,
            "status": VendorStatus.ACTIVE,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        await db.vendors.insert_one(vendor_doc)

    await db.users.insert_one(user_doc)

    return {
        "user_id": user_id,
        "email": user_data.email,
        "name": user_data.name,
        "role": user_data.role,
    }


@api_router.put("/users/{user_id}")
async def update_user(
    user_id: str, update_data: UserUpdate, admin: dict = Depends(require_admin)
):
    updates = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    result = await db.users.update_one({"user_id": user_id}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    user = await db.users.find_one({"user_id": user_id}, {"_id": 0, "password_hash": 0})
    return user


@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: dict = Depends(require_admin)):
    if admin["user_id"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    result = await db.users.delete_one({"user_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "User deleted"}


# ============== CLIENTS ROUTES ==============


@api_router.get("/clients")
async def get_clients(
    user: dict = Depends(get_current_user),
    status: Optional[str] = None,
    search: Optional[str] = None,
):
    query = {}
    if status:
        query["kyc_status"] = status
    if search:
        query["$or"] = [
            {"first_name": {"$regex": search, "$options": "i"}},
            {"last_name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}},
        ]

    clients = await db.clients.find(query, {"_id": 0}).to_list(1000)

    # Get transaction summaries for all clients
    tx_pipeline = [
        {
            "$group": {
                "_id": {"client_id": "$client_id", "type": "$transaction_type"},
                "total_amount": {"$sum": "$amount"},
                "count": {"$sum": 1},
            }
        }
    ]
    tx_summaries = await db.transactions.aggregate(tx_pipeline).to_list(10000)

    # Build lookup dict
    client_tx_map = {}
    for summary in tx_summaries:
        client_id = summary["_id"]["client_id"]
        tx_type = summary["_id"]["type"]
        if client_id not in client_tx_map:
            client_tx_map[client_id] = {
                "deposits": 0,
                "withdrawals": 0,
                "deposit_count": 0,
                "withdrawal_count": 0,
            }
        if tx_type == "deposit":
            client_tx_map[client_id]["deposits"] = summary["total_amount"]
            client_tx_map[client_id]["deposit_count"] = summary["count"]
        elif tx_type == "withdrawal":
            client_tx_map[client_id]["withdrawals"] = summary["total_amount"]
            client_tx_map[client_id]["withdrawal_count"] = summary["count"]

    # Add summaries to clients
    for client in clients:
        tx_data = client_tx_map.get(client["client_id"], {})
        client["total_deposits"] = tx_data.get("deposits", 0)
        client["total_withdrawals"] = tx_data.get("withdrawals", 0)
        client["deposit_count"] = tx_data.get("deposit_count", 0)
        client["withdrawal_count"] = tx_data.get("withdrawal_count", 0)
        client["net_balance"] = client["total_deposits"] - client["total_withdrawals"]
        client["transaction_count"] = (
            client["deposit_count"] + client["withdrawal_count"]
        )

    return clients


@api_router.get("/clients/{client_id}")
async def get_client(client_id: str, user: dict = Depends(get_current_user)):
    client = await db.clients.find_one({"client_id": client_id}, {"_id": 0})
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    # Get transaction summary
    pipeline = [
        {"$match": {"client_id": client_id}},
        {
            "$group": {
                "_id": "$transaction_type",
                "total_amount": {"$sum": "$amount"},
                "total_base_amount": {"$sum": {"$ifNull": ["$base_amount", "$amount"]}},
                "count": {"$sum": 1},
            }
        },
    ]

    tx_summary = await db.transactions.aggregate(pipeline).to_list(10)

    deposits = next(
        (x for x in tx_summary if x["_id"] == "deposit"),
        {"total_amount": 0, "count": 0},
    )
    withdrawals = next(
        (x for x in tx_summary if x["_id"] == "withdrawal"),
        {"total_amount": 0, "count": 0},
    )

    client["total_deposits"] = deposits.get("total_amount", 0)
    client["total_withdrawals"] = withdrawals.get("total_amount", 0)
    client["deposit_count"] = deposits.get("count", 0)
    client["withdrawal_count"] = withdrawals.get("count", 0)
    client["net_balance"] = deposits.get("total_amount", 0) - withdrawals.get(
        "total_amount", 0
    )
    client["transaction_count"] = deposits.get("count", 0) + withdrawals.get("count", 0)

    # Get recent transactions
    recent_txs = (
        await db.transactions.find({"client_id": client_id}, {"_id": 0})
        .sort("created_at", -1)
        .limit(10)
        .to_list(10)
    )
    client["recent_transactions"] = recent_txs

    return client


@api_router.post("/clients")
async def create_client(
    client_data: ClientCreate, user: dict = Depends(get_current_user)
):
    existing = await db.clients.find_one({"email": client_data.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Client email already exists")

    client_id = f"client_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    client_doc = {
        "client_id": client_id,
        **client_data.model_dump(),
        "kyc_status": ClientStatus.PENDING,
        "kyc_documents": [],
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    await db.clients.insert_one(client_doc)

    return await db.clients.find_one({"client_id": client_id}, {"_id": 0})


@api_router.put("/clients/{client_id}")
async def update_client(
    client_id: str, update_data: ClientUpdate, user: dict = Depends(get_current_user)
):
    updates = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    result = await db.clients.update_one({"client_id": client_id}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")

    return await db.clients.find_one({"client_id": client_id}, {"_id": 0})


@api_router.delete("/clients/{client_id}")
async def delete_client(client_id: str, user: dict = Depends(get_current_user)):
    result = await db.clients.delete_one({"client_id": client_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"message": "Client deleted"}


# ============== CLIENT BANK ACCOUNTS ROUTES ==============


@api_router.get("/clients/{client_id}/bank-accounts")
async def get_client_bank_accounts(
    client_id: str, user: dict = Depends(get_current_user)
):
    """Get all saved bank accounts for a client"""
    accounts = await db.client_bank_accounts.find(
        {"client_id": client_id}, {"_id": 0}
    ).to_list(100)
    return accounts


@api_router.post("/clients/{client_id}/bank-accounts")
async def create_client_bank_account(
    client_id: str,
    bank_name: str = Form(...),
    account_name: str = Form(...),
    account_number: str = Form(...),
    swift_iban: str = Form(None),
    currency: str = Form("USD"),
    user: dict = Depends(get_current_user),
):
    """Save a new bank account for a client"""
    # Check if client exists
    client = await db.clients.find_one({"client_id": client_id}, {"_id": 0})
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    # Check for duplicate account
    existing = await db.client_bank_accounts.find_one(
        {
            "client_id": client_id,
            "account_number": account_number,
            "bank_name": bank_name,
        }
    )
    if existing:
        return existing  # Return existing instead of creating duplicate

    bank_account_id = f"cba_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    bank_doc = {
        "bank_account_id": bank_account_id,
        "client_id": client_id,
        "bank_name": bank_name,
        "account_name": account_name,
        "account_number": account_number,
        "swift_iban": swift_iban,
        "currency": currency,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
    }

    await db.client_bank_accounts.insert_one(bank_doc)
    return await db.client_bank_accounts.find_one(
        {"bank_account_id": bank_account_id}, {"_id": 0}
    )


@api_router.put("/clients/{client_id}/bank-accounts/{bank_account_id}")
async def update_client_bank_account(
    client_id: str,
    bank_account_id: str,
    bank_name: str = Form(None),
    account_name: str = Form(None),
    account_number: str = Form(None),
    swift_iban: str = Form(None),
    currency: str = Form(None),
    user: dict = Depends(get_current_user),
):
    """Update a client's bank account"""
    updates = {}
    if bank_name:
        updates["bank_name"] = bank_name
    if account_name:
        updates["account_name"] = account_name
    if account_number:
        updates["account_number"] = account_number
    if swift_iban is not None:
        updates["swift_iban"] = swift_iban
    if currency:
        updates["currency"] = currency

    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    result = await db.client_bank_accounts.update_one(
        {"bank_account_id": bank_account_id, "client_id": client_id}, {"$set": updates}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Bank account not found")

    return await db.client_bank_accounts.find_one(
        {"bank_account_id": bank_account_id}, {"_id": 0}
    )


@api_router.delete("/clients/{client_id}/bank-accounts/{bank_account_id}")
async def delete_client_bank_account(
    client_id: str, bank_account_id: str, user: dict = Depends(get_current_user)
):
    """Delete a client's bank account"""
    result = await db.client_bank_accounts.delete_one(
        {"bank_account_id": bank_account_id, "client_id": client_id}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Bank account not found")
    return {"message": "Bank account deleted"}


# ============== TREASURY/BANK ACCOUNTS ROUTES ==============


@api_router.get("/treasury")
async def get_treasury_accounts(user: dict = Depends(get_current_user)):
    accounts = await db.treasury_accounts.find({}, {"_id": 0}).to_list(1000)
    # Add USD equivalent for each account
    for acc in accounts:
        acc["balance_usd"] = convert_to_usd(
            acc.get("balance", 0), acc.get("currency", "USD")
        )
    return accounts


@api_router.get("/treasury/{account_id}")
async def get_treasury_account(account_id: str, user: dict = Depends(get_current_user)):
    account = await db.treasury_accounts.find_one(
        {"account_id": account_id}, {"_id": 0}
    )
    if not account:
        raise HTTPException(status_code=404, detail="Treasury account not found")
    return account


@api_router.post("/treasury")
async def create_treasury_account(
    account_data: TreasuryAccountCreate,
    user: dict = Depends(require_accountant_or_admin),
):
    account_id = f"treasury_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    account_doc = {
        "account_id": account_id,
        **account_data.model_dump(exclude={"opening_balance"}),
        "balance": account_data.opening_balance,
        "opening_balance": account_data.opening_balance,
        "status": TreasuryAccountStatus.ACTIVE,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    await db.treasury_accounts.insert_one(account_doc)

    return await db.treasury_accounts.find_one({"account_id": account_id}, {"_id": 0})


@api_router.put("/treasury/{account_id}")
async def update_treasury_account(
    account_id: str,
    update_data: TreasuryAccountUpdate,
    user: dict = Depends(require_accountant_or_admin),
):
    updates = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    result = await db.treasury_accounts.update_one(
        {"account_id": account_id}, {"$set": updates}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Treasury account not found")

    return await db.treasury_accounts.find_one({"account_id": account_id}, {"_id": 0})


# Treasury Transaction History
@api_router.get("/treasury/{account_id}/history")
async def get_treasury_history(
    account_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    transaction_type: Optional[str] = None,
    limit: int = 100,
    user: dict = Depends(get_current_user),
):
    """Get transaction history for a treasury account"""
    account = await db.treasury_accounts.find_one(
        {"account_id": account_id}, {"_id": 0}
    )
    if not account:
        raise HTTPException(status_code=404, detail="Treasury account not found")

    # Build query for treasury transactions
    query = {"account_id": account_id}

    if start_date:
        query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in query:
            query["created_at"]["$lte"] = end_date
        else:
            query["created_at"] = {"$lte": end_date}
    if transaction_type:
        query["transaction_type"] = transaction_type

    # Get treasury-specific transactions (these are the canonical records with proper currency conversion)
    treasury_txs = (
        await db.treasury_transactions.find(query, {"_id": 0})
        .sort("created_at", -1)
        .to_list(limit)
    )

    # Adjust amounts for display - outflows should be negative
    outflow_types = ["debt_payment", "withdrawal", "transfer_out", "expense"]
    for ttx in treasury_txs:
        if ttx.get("transaction_type") in outflow_types:
            ttx["amount"] = -abs(ttx.get("amount", 0))

    # Get transaction IDs that already have treasury transaction records
    existing_tx_ids = set()
    for ttx in treasury_txs:
        if ttx.get("transaction_id"):
            existing_tx_ids.add(ttx.get("transaction_id"))

    # Only get regular transactions that DON'T have treasury transaction records yet
    # (for backwards compatibility with old data that might not have treasury_transactions)
    tx_query = {
        "destination_account_id": account_id,
        "status": {"$in": ["approved", "completed"]},
    }
    if start_date:
        tx_query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in tx_query:
            tx_query["created_at"]["$lte"] = end_date
        else:
            tx_query["created_at"] = {"$lte": end_date}

    regular_txs = (
        await db.transactions.find(tx_query, {"_id": 0})
        .sort("created_at", -1)
        .to_list(limit)
    )

    # Convert regular transactions to history format ONLY if they don't already have a treasury_transaction
    for tx in regular_txs:
        if tx.get("transaction_id") not in existing_tx_ids:
            treasury_txs.append(
                {
                    "treasury_transaction_id": tx.get("transaction_id"),
                    "account_id": account_id,
                    "transaction_type": tx.get("transaction_type"),
                    "amount": (
                        tx.get("amount")
                        if tx.get("transaction_type") == "deposit"
                        else -tx.get("amount", 0)
                    ),
                    "currency": account.get("currency", "USD"),
                    "reference": f"{tx.get('transaction_type', '').capitalize()}: {tx.get('client_name', 'Unknown')} - {tx.get('reference', '')}",
                    "client_id": tx.get("client_id"),
                    "client_name": tx.get("client_name"),
                    "created_at": tx.get("processed_at") or tx.get("created_at"),
                    "created_by": tx.get("processed_by"),
                    "created_by_name": tx.get("processed_by_name"),
                }
            )

    # Sort combined list by date
    treasury_txs.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return treasury_txs[:limit]


@api_router.delete("/treasury/{account_id}")
async def delete_treasury_account(account_id: str, user: dict = Depends(require_admin)):
    result = await db.treasury_accounts.delete_one({"account_id": account_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Treasury account not found")
    return {"message": "Treasury account deleted"}


# Inter-Treasury Transfer
class TreasuryTransferRequest(BaseModel):
    source_account_id: str
    destination_account_id: str
    amount: float
    exchange_rate: Optional[float] = 1.0
    notes: Optional[str] = None


@api_router.post("/treasury/transfer")
async def inter_treasury_transfer(
    transfer: TreasuryTransferRequest, user: dict = Depends(require_accountant_or_admin)
):
    """Transfer funds between treasury accounts"""
    if transfer.source_account_id == transfer.destination_account_id:
        raise HTTPException(
            status_code=400, detail="Source and destination accounts must be different"
        )

    if transfer.amount <= 0:
        raise HTTPException(status_code=400, detail="Transfer amount must be positive")

    # Get source account
    source = await db.treasury_accounts.find_one(
        {"account_id": transfer.source_account_id}, {"_id": 0}
    )
    if not source:
        raise HTTPException(status_code=404, detail="Source account not found")

    # Get destination account
    destination = await db.treasury_accounts.find_one(
        {"account_id": transfer.destination_account_id}, {"_id": 0}
    )
    if not destination:
        raise HTTPException(status_code=404, detail="Destination account not found")

    # Check sufficient balance
    if source.get("balance", 0) < transfer.amount:
        raise HTTPException(
            status_code=400, detail="Insufficient balance in source account"
        )

    now = datetime.now(timezone.utc)
    transfer_id = f"trf_{uuid.uuid4().hex[:12]}"

    # Calculate destination amount based on exchange rate
    destination_amount = round(transfer.amount * (transfer.exchange_rate or 1.0), 2)

    # Deduct from source
    await db.treasury_accounts.update_one(
        {"account_id": transfer.source_account_id},
        {
            "$inc": {"balance": -transfer.amount},
            "$set": {"updated_at": now.isoformat()},
        },
    )

    # Add to destination
    await db.treasury_accounts.update_one(
        {"account_id": transfer.destination_account_id},
        {
            "$inc": {"balance": destination_amount},
            "$set": {"updated_at": now.isoformat()},
        },
    )

    # Record source transaction (transfer out)
    source_tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
    source_tx_doc = {
        "treasury_transaction_id": source_tx_id,
        "account_id": transfer.source_account_id,
        "transaction_type": "transfer_out",
        "amount": -transfer.amount,
        "currency": source.get("currency", "USD"),
        "reference": f"Transfer to {destination.get('account_name')}",
        "transfer_id": transfer_id,
        "related_account_id": transfer.destination_account_id,
        "related_account_name": destination.get("account_name"),
        "exchange_rate": transfer.exchange_rate,
        "destination_amount": destination_amount,
        "destination_currency": destination.get("currency", "USD"),
        "notes": transfer.notes,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.treasury_transactions.insert_one(source_tx_doc)

    # Record destination transaction (transfer in)
    dest_tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
    dest_tx_doc = {
        "treasury_transaction_id": dest_tx_id,
        "account_id": transfer.destination_account_id,
        "transaction_type": "transfer_in",
        "amount": destination_amount,
        "currency": destination.get("currency", "USD"),
        "reference": f"Transfer from {source.get('account_name')}",
        "transfer_id": transfer_id,
        "related_account_id": transfer.source_account_id,
        "related_account_name": source.get("account_name"),
        "exchange_rate": transfer.exchange_rate,
        "source_amount": transfer.amount,
        "source_currency": source.get("currency", "USD"),
        "notes": transfer.notes,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.treasury_transactions.insert_one(dest_tx_doc)

    # Return transfer details
    return {
        "transfer_id": transfer_id,
        "source_account": source.get("account_name"),
        "source_currency": source.get("currency", "USD"),
        "source_amount": transfer.amount,
        "destination_account": destination.get("account_name"),
        "destination_currency": destination.get("currency", "USD"),
        "destination_amount": destination_amount,
        "exchange_rate": transfer.exchange_rate,
        "notes": transfer.notes,
        "created_at": now.isoformat(),
        "created_by_name": user["name"],
    }


# ============== LP (LIQUIDITY PROVIDER) ROUTES ==============


@api_router.get("/lp")
async def get_lp_accounts(user: dict = Depends(get_current_user)):
    """Get all LP accounts"""
    accounts = await db.lp_accounts.find({}, {"_id": 0}).to_list(1000)
    return accounts


@api_router.get("/lp/dashboard")
async def get_lp_dashboard(user: dict = Depends(get_current_user)):
    """Get LP dashboard with summary statistics"""
    accounts = await db.lp_accounts.find({}, {"_id": 0}).to_list(1000)

    total_balance = sum(a.get("balance", 0) for a in accounts)
    total_deposits = sum(a.get("total_deposits", 0) for a in accounts)
    total_withdrawals = sum(a.get("total_withdrawals", 0) for a in accounts)
    active_count = sum(1 for a in accounts if a.get("status") == LPAccountStatus.ACTIVE)

    # Get recent transactions
    recent_txs = (
        await db.lp_transactions.find({}, {"_id": 0})
        .sort("created_at", -1)
        .limit(10)
        .to_list(10)
    )

    return {
        "total_balance": total_balance,
        "total_deposits": total_deposits,
        "total_withdrawals": total_withdrawals,
        "active_lp_count": active_count,
        "total_lp_count": len(accounts),
        "accounts": accounts,
        "recent_transactions": recent_txs,
    }


@api_router.get("/lp/{lp_id}")
async def get_lp_account(lp_id: str, user: dict = Depends(get_current_user)):
    """Get a specific LP account"""
    account = await db.lp_accounts.find_one({"lp_id": lp_id}, {"_id": 0})
    if not account:
        raise HTTPException(status_code=404, detail="LP account not found")
    return account


@api_router.post("/lp")
async def create_lp_account(
    lp_data: LPAccountCreate, user: dict = Depends(require_accountant_or_admin)
):
    """Create a new LP account"""
    lp_id = f"lp_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    account_doc = {
        "lp_id": lp_id,
        "lp_name": lp_data.lp_name,
        "account_number": lp_data.account_number,
        "bank_name": lp_data.bank_name,
        "swift_code": lp_data.swift_code,
        "currency": lp_data.currency,
        "contact_person": lp_data.contact_person,
        "contact_email": lp_data.contact_email,
        "contact_phone": lp_data.contact_phone,
        "notes": lp_data.notes,
        "balance": 0,
        "total_deposits": 0,
        "total_withdrawals": 0,
        "transaction_count": 0,
        "status": LPAccountStatus.ACTIVE,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.lp_accounts.insert_one(account_doc)
    return await db.lp_accounts.find_one({"lp_id": lp_id}, {"_id": 0})


@api_router.put("/lp/{lp_id}")
async def update_lp_account(
    lp_id: str,
    lp_data: LPAccountUpdate,
    user: dict = Depends(require_accountant_or_admin),
):
    """Update an LP account"""
    account = await db.lp_accounts.find_one({"lp_id": lp_id}, {"_id": 0})
    if not account:
        raise HTTPException(status_code=404, detail="LP account not found")

    updates = {k: v for k, v in lp_data.model_dump().items() if v is not None}
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    await db.lp_accounts.update_one({"lp_id": lp_id}, {"$set": updates})
    return await db.lp_accounts.find_one({"lp_id": lp_id}, {"_id": 0})


@api_router.get("/lp/{lp_id}/transactions")
async def get_lp_transactions(
    lp_id: str, user: dict = Depends(get_current_user), limit: int = 100
):
    """Get transactions for a specific LP account"""
    account = await db.lp_accounts.find_one({"lp_id": lp_id}, {"_id": 0})
    if not account:
        raise HTTPException(status_code=404, detail="LP account not found")

    transactions = (
        await db.lp_transactions.find({"lp_id": lp_id}, {"_id": 0})
        .sort("created_at", -1)
        .to_list(limit)
    )

    return transactions


@api_router.post("/lp/{lp_id}/deposit")
async def create_lp_deposit(
    lp_id: str,
    tx_data: LPTransactionCreate,
    user: dict = Depends(require_accountant_or_admin),
):
    """Create a deposit to LP (sending funds TO the LP)"""
    account = await db.lp_accounts.find_one({"lp_id": lp_id}, {"_id": 0})
    if not account:
        raise HTTPException(status_code=404, detail="LP account not found")

    if tx_data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    now = datetime.now(timezone.utc)
    tx_id = f"lptx_{uuid.uuid4().hex[:12]}"

    # If treasury account specified, deduct from it
    treasury_name = None
    treasury_deduct_amount = tx_data.amount
    if tx_data.treasury_account_id:
        treasury = await db.treasury_accounts.find_one(
            {"account_id": tx_data.treasury_account_id}, {"_id": 0}
        )
        if not treasury:
            raise HTTPException(status_code=404, detail="Treasury account not found")

        # Convert amount if currencies differ
        treasury_currency = treasury.get("currency", "USD")
        if treasury_currency.upper() != tx_data.currency.upper():
            treasury_deduct_amount = convert_currency(
                tx_data.amount, tx_data.currency, treasury_currency
            )

        if treasury.get("balance", 0) < treasury_deduct_amount:
            raise HTTPException(
                status_code=400,
                detail=f"Insufficient treasury balance. Required: {treasury_deduct_amount:,.2f} {treasury_currency}",
            )

        treasury_name = treasury.get("account_name")

        # Deduct from treasury (in treasury's currency)
        await db.treasury_accounts.update_one(
            {"account_id": tx_data.treasury_account_id},
            {
                "$inc": {"balance": -treasury_deduct_amount},
                "$set": {"updated_at": now.isoformat()},
            },
        )

        # Record treasury transaction
        conversion_note = (
            f" (Converted from {tx_data.amount:,.2f} {tx_data.currency})"
            if treasury_currency.upper() != tx_data.currency.upper()
            else ""
        )
        await db.treasury_transactions.insert_one(
            {
                "treasury_transaction_id": f"ttx_{uuid.uuid4().hex[:12]}",
                "account_id": tx_data.treasury_account_id,
                "account_name": treasury_name,
                "transaction_type": "lp_deposit",
                "amount": -treasury_deduct_amount,
                "currency": treasury_currency,
                "original_amount": tx_data.amount,
                "original_currency": tx_data.currency,
                "reference": f"Deposit to LP: {account['lp_name']}{conversion_note}",
                "lp_transaction_id": tx_id,
                "created_at": now.isoformat(),
                "created_by": user["user_id"],
                "created_by_name": user["name"],
            }
        )

    # Create LP transaction
    tx_doc = {
        "lp_transaction_id": tx_id,
        "lp_id": lp_id,
        "lp_name": account["lp_name"],
        "transaction_type": LPTransactionType.DEPOSIT,
        "amount": tx_data.amount,
        "currency": tx_data.currency,
        "treasury_account_id": tx_data.treasury_account_id,
        "treasury_name": treasury_name,
        "reference": tx_data.reference or f"DEP-{tx_id[-8:].upper()}",
        "notes": tx_data.notes,
        "balance_before": account.get("balance", 0),
        "balance_after": account.get("balance", 0) + tx_data.amount,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.lp_transactions.insert_one(tx_doc)

    # Update LP account balance
    await db.lp_accounts.update_one(
        {"lp_id": lp_id},
        {
            "$inc": {
                "balance": tx_data.amount,
                "total_deposits": tx_data.amount,
                "transaction_count": 1,
            },
            "$set": {"updated_at": now.isoformat()},
        },
    )

    tx_doc.pop("_id", None)
    return tx_doc


@api_router.post("/lp/{lp_id}/withdraw")
async def create_lp_withdrawal(
    lp_id: str,
    tx_data: LPTransactionCreate,
    user: dict = Depends(require_accountant_or_admin),
):
    """Create a withdrawal from LP (receiving funds FROM the LP)"""
    account = await db.lp_accounts.find_one({"lp_id": lp_id}, {"_id": 0})
    if not account:
        raise HTTPException(status_code=404, detail="LP account not found")

    if tx_data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    if account.get("balance", 0) < tx_data.amount:
        raise HTTPException(status_code=400, detail="Insufficient LP balance")

    now = datetime.now(timezone.utc)
    tx_id = f"lptx_{uuid.uuid4().hex[:12]}"

    # If treasury account specified, add to it
    treasury_name = None
    treasury_add_amount = tx_data.amount
    if tx_data.treasury_account_id:
        treasury = await db.treasury_accounts.find_one(
            {"account_id": tx_data.treasury_account_id}, {"_id": 0}
        )
        if not treasury:
            raise HTTPException(status_code=404, detail="Treasury account not found")

        treasury_name = treasury.get("account_name")

        # Convert amount if currencies differ
        treasury_currency = treasury.get("currency", "USD")
        if treasury_currency.upper() != tx_data.currency.upper():
            treasury_add_amount = convert_currency(
                tx_data.amount, tx_data.currency, treasury_currency
            )

        # Add to treasury (in treasury's currency)
        await db.treasury_accounts.update_one(
            {"account_id": tx_data.treasury_account_id},
            {
                "$inc": {"balance": treasury_add_amount},
                "$set": {"updated_at": now.isoformat()},
            },
        )

        # Record treasury transaction
        conversion_note = (
            f" (Converted from {tx_data.amount:,.2f} {tx_data.currency})"
            if treasury_currency.upper() != tx_data.currency.upper()
            else ""
        )
        await db.treasury_transactions.insert_one(
            {
                "treasury_transaction_id": f"ttx_{uuid.uuid4().hex[:12]}",
                "account_id": tx_data.treasury_account_id,
                "account_name": treasury_name,
                "transaction_type": "lp_withdrawal",
                "amount": treasury_add_amount,
                "currency": treasury_currency,
                "original_amount": tx_data.amount,
                "original_currency": tx_data.currency,
                "reference": f"Withdrawal from LP: {account['lp_name']}{conversion_note}",
                "lp_transaction_id": tx_id,
                "created_at": now.isoformat(),
                "created_by": user["user_id"],
                "created_by_name": user["name"],
            }
        )

    # Create LP transaction
    tx_doc = {
        "lp_transaction_id": tx_id,
        "lp_id": lp_id,
        "lp_name": account["lp_name"],
        "transaction_type": LPTransactionType.WITHDRAWAL,
        "amount": tx_data.amount,
        "currency": tx_data.currency,
        "treasury_account_id": tx_data.treasury_account_id,
        "treasury_name": treasury_name,
        "reference": tx_data.reference or f"WTH-{tx_id[-8:].upper()}",
        "notes": tx_data.notes,
        "balance_before": account.get("balance", 0),
        "balance_after": account.get("balance", 0) - tx_data.amount,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.lp_transactions.insert_one(tx_doc)

    # Update LP account balance
    await db.lp_accounts.update_one(
        {"lp_id": lp_id},
        {
            "$inc": {
                "balance": -tx_data.amount,
                "total_withdrawals": tx_data.amount,
                "transaction_count": 1,
            },
            "$set": {"updated_at": now.isoformat()},
        },
    )

    tx_doc.pop("_id", None)
    return tx_doc


@api_router.get("/lp/export/csv")
async def export_lp_csv(user: dict = Depends(get_current_user)):
    """Export LP accounts and transactions to CSV"""
    import csv
    import io

    accounts = await db.lp_accounts.find({}, {"_id": 0}).to_list(1000)
    transactions = (
        await db.lp_transactions.find({}, {"_id": 0})
        .sort("created_at", -1)
        .to_list(5000)
    )

    output = io.StringIO()

    # Write accounts
    output.write("=== LP ACCOUNTS ===\n")
    if accounts:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "lp_id",
                "lp_name",
                "currency",
                "balance",
                "total_deposits",
                "total_withdrawals",
                "status",
            ],
        )
        writer.writeheader()
        for acc in accounts:
            writer.writerow({k: acc.get(k, "") for k in writer.fieldnames})

    output.write("\n=== LP TRANSACTIONS ===\n")
    if transactions:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "lp_transaction_id",
                "lp_name",
                "transaction_type",
                "amount",
                "currency",
                "reference",
                "created_at",
                "created_by_name",
            ],
        )
        writer.writeheader()
        for tx in transactions:
            writer.writerow({k: tx.get(k, "") for k in writer.fieldnames})

    from fastapi.responses import StreamingResponse

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=lp_export_{datetime.now().strftime('%Y%m%d')}.csv"
        },
    )


# ============== PSP ROUTES ==============


@api_router.get("/psp")
async def get_psps(user: dict = Depends(get_current_user)):
    psps = await db.psps.find({}, {"_id": 0}).to_list(1000)

    # Batch fetch treasury accounts to avoid N+1 queries
    treasury_ids = list(
        set(
            psp.get("settlement_destination_id")
            for psp in psps
            if psp.get("settlement_destination_id")
        )
    )
    treasury_map = {}
    if treasury_ids:
        treasuries = await db.treasury_accounts.find(
            {"account_id": {"$in": treasury_ids}}, {"_id": 0}
        ).to_list(len(treasury_ids))
        treasury_map = {t["account_id"]: t for t in treasuries}

    for psp in psps:
        if psp.get("settlement_destination_id"):
            dest = treasury_map.get(psp["settlement_destination_id"])
            psp["settlement_destination_name"] = (
                dest["account_name"] if dest else "Unknown"
            )
            psp["settlement_destination_bank"] = dest.get("bank_name") if dest else None
    return psps


@api_router.get("/psp/{psp_id}")
async def get_psp(psp_id: str, user: dict = Depends(get_current_user)):
    psp = await db.psps.find_one({"psp_id": psp_id}, {"_id": 0})
    if not psp:
        raise HTTPException(status_code=404, detail="PSP not found")
    return psp


@api_router.post("/psp")
async def create_psp(
    psp_data: PSPCreate, user: dict = Depends(require_accountant_or_admin)
):
    # Verify settlement destination exists
    dest = await db.treasury_accounts.find_one(
        {"account_id": psp_data.settlement_destination_id}, {"_id": 0}
    )
    if not dest:
        raise HTTPException(
            status_code=404, detail="Settlement destination account not found"
        )

    psp_id = f"psp_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    psp_doc = {
        "psp_id": psp_id,
        **psp_data.model_dump(),
        "total_volume": 0.0,
        "total_commission": 0.0,
        "pending_settlement": 0.0,
        "status": PSPStatus.ACTIVE,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    await db.psps.insert_one(psp_doc)
    return await db.psps.find_one({"psp_id": psp_id}, {"_id": 0})


@api_router.put("/psp/{psp_id}")
async def update_psp(
    psp_id: str,
    update_data: PSPUpdate,
    user: dict = Depends(require_accountant_or_admin),
):
    updates = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    # Verify settlement destination if being updated
    if updates.get("settlement_destination_id"):
        dest = await db.treasury_accounts.find_one(
            {"account_id": updates["settlement_destination_id"]}, {"_id": 0}
        )
        if not dest:
            raise HTTPException(
                status_code=404, detail="Settlement destination account not found"
            )

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    result = await db.psps.update_one({"psp_id": psp_id}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="PSP not found")

    return await db.psps.find_one({"psp_id": psp_id}, {"_id": 0})


@api_router.delete("/psp/{psp_id}")
async def delete_psp(psp_id: str, user: dict = Depends(require_admin)):
    result = await db.psps.delete_one({"psp_id": psp_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="PSP not found")
    return {"message": "PSP deleted"}


# PSP Settlements
@api_router.get("/psp/{psp_id}/settlements")
async def get_psp_settlements(psp_id: str, user: dict = Depends(get_current_user)):
    settlements = (
        await db.psp_settlements.find({"psp_id": psp_id}, {"_id": 0})
        .sort("created_at", -1)
        .to_list(1000)
    )
    return settlements


@api_router.get("/psp-settlements")
async def get_all_settlements(
    user: dict = Depends(get_current_user),
    status: Optional[str] = None,
    limit: int = 100,
):
    query = {}
    if status:
        query["status"] = status
    settlements = (
        await db.psp_settlements.find(query, {"_id": 0})
        .sort("created_at", -1)
        .to_list(limit)
    )
    return settlements


@api_router.post("/psp/{psp_id}/settle")
async def create_settlement(
    psp_id: str, user: dict = Depends(require_accountant_or_admin)
):
    """Create a settlement for pending PSP transactions"""
    psp = await db.psps.find_one({"psp_id": psp_id}, {"_id": 0})
    if not psp:
        raise HTTPException(status_code=404, detail="PSP not found")

    # Get pending transactions for this PSP
    pending_txs = await db.transactions.find(
        {
            "psp_id": psp_id,
            "status": {
                "$in": [TransactionStatus.APPROVED, TransactionStatus.COMPLETED]
            },
            "settled": {"$ne": True},
        },
        {"_id": 0},
    ).to_list(1000)

    if not pending_txs:
        raise HTTPException(status_code=400, detail="No pending transactions to settle")

    # Calculate totals
    gross_amount = sum(tx["amount"] for tx in pending_txs)

    # Commission
    commission_rate = psp.get("commission_rate", 0) / 100
    commission_amount = round(gross_amount * commission_rate, 2)

    # Reserve Fund (from PSP default rate)
    reserve_fund_rate = (
        psp.get("reserve_fund_rate", psp.get("chargeback_rate", 0)) / 100
    )
    reserve_fund_amount = round(gross_amount * reserve_fund_rate, 2)

    # Extra charges (sum from individual transactions)
    total_extra_charges = sum(tx.get("psp_extra_charges", 0) for tx in pending_txs)

    # Gateway fees (per transaction)
    gateway_fee = psp.get("gateway_fee", 0)
    total_gateway_fees = round(gateway_fee * len(pending_txs), 2)

    # Individual transaction reserve fund amounts (override PSP rate if set per transaction)
    total_tx_reserve = sum(
        tx.get("psp_reserve_fund_amount", tx.get("psp_chargeback_amount", 0))
        for tx in pending_txs
    )
    # Use transaction-level amounts if any, otherwise use PSP rate
    final_reserve_fund = (
        total_tx_reserve if total_tx_reserve > 0 else reserve_fund_amount
    )

    # Net amount = Gross - Commission - Reserve Fund - Extra Charges - Gateway Fees
    net_amount = (
        gross_amount
        - commission_amount
        - final_reserve_fund
        - total_extra_charges
        - total_gateway_fees
    )

    settlement_id = f"stl_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    settlement_date = now + timedelta(days=psp.get("settlement_days", 1))

    settlement_doc = {
        "settlement_id": settlement_id,
        "psp_id": psp_id,
        "psp_name": psp["psp_name"],
        "gross_amount": gross_amount,
        "commission_rate": psp.get("commission_rate", 0),
        "commission_amount": commission_amount,
        "reserve_fund_rate": psp.get(
            "reserve_fund_rate", psp.get("chargeback_rate", 0)
        ),
        "reserve_fund_amount": final_reserve_fund,
        "chargeback_rate": psp.get("reserve_fund_rate", psp.get("chargeback_rate", 0)),
        "chargeback_amount": final_reserve_fund,
        "extra_charges": total_extra_charges,
        "gateway_fees": total_gateway_fees,
        "total_deductions": commission_amount
        + final_reserve_fund
        + total_extra_charges
        + total_gateway_fees,
        "net_amount": net_amount,
        "holding_days": psp.get("holding_days", 0),
        "transaction_count": len(pending_txs),
        "transaction_ids": [tx["transaction_id"] for tx in pending_txs],
        "settlement_destination_id": psp["settlement_destination_id"],
        "status": PSPSettlementStatus.PENDING,
        "expected_settlement_date": settlement_date.isoformat(),
        "created_at": now.isoformat(),
        "settled_at": None,
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.psp_settlements.insert_one(settlement_doc)

    # Mark transactions as pending settlement
    await db.transactions.update_many(
        {"transaction_id": {"$in": [tx["transaction_id"] for tx in pending_txs]}},
        {"$set": {"settlement_id": settlement_id, "settlement_status": "pending"}},
    )

    # Update PSP stats
    await db.psps.update_one(
        {"psp_id": psp_id}, {"$inc": {"pending_settlement": net_amount}}
    )

    return await db.psp_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )


@api_router.post("/psp-settlements/{settlement_id}/complete")
async def complete_settlement(
    settlement_id: str, user: dict = Depends(require_accountant_or_admin)
):
    """Mark a settlement as completed and transfer funds to treasury"""
    settlement = await db.psp_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )
    if not settlement:
        raise HTTPException(status_code=404, detail="Settlement not found")

    if settlement["status"] == PSPSettlementStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Settlement already completed")

    now = datetime.now(timezone.utc)

    # Get destination treasury account for currency conversion
    dest = await db.treasury_accounts.find_one(
        {"account_id": settlement["settlement_destination_id"]}, {"_id": 0}
    )
    dest_currency = dest.get("currency", "USD") if dest else "USD"

    # Settlement amounts are in USD (transaction currency); convert to treasury currency
    settlement_net = settlement["net_amount"]
    treasury_amount = convert_currency(settlement_net, "USD", dest_currency)

    # Update treasury balance (in treasury account's currency)
    await db.treasury_accounts.update_one(
        {"account_id": settlement["settlement_destination_id"]},
        {"$inc": {"balance": treasury_amount}, "$set": {"updated_at": now.isoformat()}},
    )

    # Update settlement status
    await db.psp_settlements.update_one(
        {"settlement_id": settlement_id},
        {
            "$set": {
                "status": PSPSettlementStatus.COMPLETED,
                "settled_at": now.isoformat(),
            }
        },
    )

    # Mark transactions as settled
    await db.transactions.update_many(
        {"settlement_id": settlement_id},
        {"$set": {"settled": True, "settlement_status": "completed"}},
    )

    # Update PSP stats
    psp = await db.psps.find_one({"psp_id": settlement["psp_id"]}, {"_id": 0})
    if psp:
        await db.psps.update_one(
            {"psp_id": settlement["psp_id"]},
            {
                "$inc": {
                    "total_volume": settlement["gross_amount"],
                    "total_commission": settlement["commission_amount"],
                    "pending_settlement": -settlement["net_amount"],
                }
            },
        )

    return await db.psp_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )


# Get pending PSP transactions (not yet settled)
@api_router.get("/psp/{psp_id}/pending-transactions")
async def get_psp_pending_transactions(
    psp_id: str, user: dict = Depends(get_current_user)
):
    """Get all pending/approved transactions for a PSP that haven't been settled"""
    transactions = (
        await db.transactions.find(
            {
                "psp_id": psp_id,
                "destination_type": "psp",
                "status": {
                    "$in": [TransactionStatus.PENDING, TransactionStatus.APPROVED]
                },
                "settled": {"$ne": True},
            },
            {"_id": 0},
        )
        .sort("created_at", -1)
        .to_list(1000)
    )
    return transactions


# Get PSP dashboard summary
@api_router.get("/psp-summary")
async def get_psp_summary(user: dict = Depends(get_current_user)):
    """Get summary of all PSPs with pending settlements"""
    psps = await db.psps.find({"status": PSPStatus.ACTIVE}, {"_id": 0}).to_list(1000)
    now = datetime.now(timezone.utc)

    result = []
    for psp in psps:
        # Get pending transactions count and amount
        pending_txs = await db.transactions.find(
            {
                "psp_id": psp["psp_id"],
                "destination_type": "psp",
                "status": {
                    "$in": [TransactionStatus.PENDING, TransactionStatus.APPROVED]
                },
                "settled": {"$ne": True},
            },
            {"_id": 0},
        ).to_list(1000)

        pending_count = len(pending_txs)
        pending_amount_gross = sum(
            tx.get("psp_net_amount", tx.get("amount", 0)) for tx in pending_txs
        )

        # Check for overdue settlements
        overdue_count = 0
        for tx in pending_txs:
            exp_date = tx.get("psp_expected_settlement_date")
            if exp_date:
                exp_dt = datetime.fromisoformat(exp_date.replace("Z", "+00:00"))
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < now:
                    overdue_count += 1

        # Calculate reserve fund held from pending transactions
        reserve_fund_rate = (
            psp.get("reserve_fund_rate", psp.get("chargeback_rate", 0)) / 100
        )
        reserve_from_pending = 0
        for tx in pending_txs:
            rf = tx.get("psp_reserve_fund_amount", tx.get("psp_chargeback_amount", 0))
            if rf > 0:
                reserve_from_pending += rf
            else:
                reserve_from_pending += round(
                    tx.get("amount", 0) * reserve_fund_rate, 2
                )

        # Pending Amount = Gross - Commission - Reserve Fund
        pending_amount = round(pending_amount_gross - reserve_from_pending, 2)

        # Total reserve held includes pending + settled unreleased
        total_reserve_held = reserve_from_pending

        # Also count released/unreleased reserve funds from settled transactions
        settled_with_reserve = await db.transactions.find(
            {
                "psp_id": psp["psp_id"],
                "destination_type": "psp",
                "settled": True,
                "$or": [
                    {"psp_reserve_fund_amount": {"$gt": 0}},
                    {"psp_chargeback_amount": {"$gt": 0}},
                ],
            },
            {
                "_id": 0,
                "psp_reserve_fund_amount": 1,
                "psp_chargeback_amount": 1,
                "reserve_fund_released": 1,
            },
        ).to_list(10000)

        held_from_settled = sum(
            tx.get("psp_reserve_fund_amount", tx.get("psp_chargeback_amount", 0))
            for tx in settled_with_reserve
            if not tx.get("reserve_fund_released")
        )
        total_reserve_held += held_from_settled

        # Get settlement destination
        dest = await db.treasury_accounts.find_one(
            {"account_id": psp.get("settlement_destination_id")}, {"_id": 0}
        )

        result.append(
            {
                **psp,
                "pending_transactions_count": pending_count,
                "pending_amount": pending_amount,
                "overdue_count": overdue_count,
                "total_reserve_fund_held": round(total_reserve_held, 2),
                "settlement_destination_name": (
                    dest["account_name"] if dest else "Unknown"
                ),
                "settlement_destination_bank": dest.get("bank_name") if dest else None,
            }
        )

    return result


# Model for PSP transaction charges
class PSPTransactionCharges(BaseModel):
    reserve_fund_amount: float = 0  # Reserve fund amount for this transaction
    extra_charges: float = 0  # Extra charges for this transaction
    charges_description: Optional[str] = None  # Description of charges


@api_router.put("/psp/transactions/{transaction_id}/charges")
async def update_psp_transaction_charges(
    transaction_id: str,
    charges: PSPTransactionCharges,
    user: dict = Depends(get_current_user),
):
    """Record reserve fund and extra charges on a PSP transaction"""
    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.get("destination_type") != "psp":
        raise HTTPException(
            status_code=400, detail="Transaction is not a PSP transaction"
        )

    if tx.get("settled"):
        raise HTTPException(
            status_code=400, detail="Cannot update charges on settled transaction"
        )

    now = datetime.now(timezone.utc)

    # Calculate new net amount
    gross_amount = tx.get("amount", 0)
    commission = tx.get("psp_commission_amount", 0)
    new_net = (
        gross_amount - commission - charges.reserve_fund_amount - charges.extra_charges
    )

    updates = {
        "psp_reserve_fund_amount": charges.reserve_fund_amount,
        "psp_chargeback_amount": charges.reserve_fund_amount,
        "psp_extra_charges": charges.extra_charges,
        "psp_charges_description": charges.charges_description,
        "psp_total_deductions": commission
        + charges.reserve_fund_amount
        + charges.extra_charges,
        "psp_net_amount": new_net,
        "charges_updated_at": now.isoformat(),
        "charges_updated_by": user["user_id"],
        "charges_updated_by_name": user["name"],
    }

    await db.transactions.update_one(
        {"transaction_id": transaction_id}, {"$set": updates}
    )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


# Mark single PSP transaction as awaiting settlement (holding period)
@api_router.post("/psp/transactions/{transaction_id}/mark-awaiting")
async def mark_psp_transaction_awaiting(
    transaction_id: str, user: dict = Depends(require_admin)
):
    """Mark a PSP transaction as awaiting settlement (in holding period)"""
    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.get("destination_type") != "psp":
        raise HTTPException(
            status_code=400, detail="Transaction is not a PSP transaction"
        )

    if tx.get("settled"):
        raise HTTPException(status_code=400, detail="Transaction already settled")

    now = datetime.now(timezone.utc)

    # Get PSP info for holding days
    psp = await db.psps.find_one({"psp_id": tx.get("psp_id")}, {"_id": 0})
    holding_days = psp.get("holding_days", 0) if psp else 0
    release_date = (
        (now + timedelta(days=holding_days)).isoformat()
        if holding_days > 0
        else now.isoformat()
    )

    # Mark transaction as awaiting settlement
    await db.transactions.update_one(
        {"transaction_id": transaction_id},
        {
            "$set": {
                "settlement_status": "awaiting",
                "psp_holding_release_date": release_date,
                "awaiting_marked_at": now.isoformat(),
                "awaiting_marked_by": user["user_id"],
                "awaiting_marked_by_name": user["name"],
            }
        },
    )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


# Record actual payment received from PSP (completes settlement)
@api_router.post("/psp/transactions/{transaction_id}/record-payment")
async def record_psp_payment(
    transaction_id: str,
    destination_account_id: Optional[str] = None,
    actual_amount_received: Optional[float] = None,
    user: dict = Depends(require_admin),
):
    """Record actual payment received from PSP and transfer to treasury"""
    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.get("destination_type") != "psp":
        raise HTTPException(
            status_code=400, detail="Transaction is not a PSP transaction"
        )

    if tx.get("settled"):
        raise HTTPException(status_code=400, detail="Transaction already settled")

    now = datetime.now(timezone.utc)

    # Get PSP info for destination
    psp = await db.psps.find_one({"psp_id": tx.get("psp_id")}, {"_id": 0})
    dest_account_id = destination_account_id or (
        psp.get("settlement_destination_id") if psp else None
    )

    if not dest_account_id:
        raise HTTPException(status_code=400, detail="No destination account specified")

    # Get destination account
    dest = await db.treasury_accounts.find_one(
        {"account_id": dest_account_id}, {"_id": 0}
    )
    if not dest:
        raise HTTPException(
            status_code=404, detail="Destination treasury account not found"
        )

    # Amount to settle - use actual amount if provided, otherwise calculated net
    expected_amount = tx.get("psp_net_amount", tx.get("amount", 0))
    settle_amount = (
        actual_amount_received
        if actual_amount_received is not None
        else expected_amount
    )
    variance = (
        settle_amount - expected_amount if actual_amount_received is not None else 0
    )

    # Currency conversion: convert from transaction currency to treasury account currency
    tx_currency = tx.get("currency", "USD")
    dest_currency = dest.get("currency", "USD")
    treasury_amount = convert_currency(settle_amount, tx_currency, dest_currency)

    # Update treasury balance (in treasury account's currency)
    await db.treasury_accounts.update_one(
        {"account_id": dest_account_id},
        {"$inc": {"balance": treasury_amount}, "$set": {"updated_at": now.isoformat()}},
    )

    # Add treasury transaction record
    treasury_tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
    conversion_note = (
        f" (Converted: {tx_currency} {settle_amount:,.2f} -> {dest_currency} {treasury_amount:,.2f})"
        if tx_currency != dest_currency
        else ""
    )
    treasury_tx = {
        "treasury_transaction_id": treasury_tx_id,
        "account_id": dest_account_id,
        "account_name": dest["account_name"],
        "transaction_type": "psp_settlement",
        "amount": treasury_amount,
        "currency": dest_currency,
        "original_amount": settle_amount,
        "original_currency": tx_currency,
        "reference": f"PSP Settlement - {tx.get('reference', transaction_id)}",
        "description": f"Settlement from {tx.get('psp_name', 'PSP')} - Expected: {tx_currency} {expected_amount:,.2f}, Received: {tx_currency} {settle_amount:,.2f}{conversion_note}",
        "related_transaction_id": transaction_id,
        "psp_id": tx.get("psp_id"),
        "psp_name": tx.get("psp_name"),
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.treasury_transactions.insert_one(treasury_tx)

    # Mark transaction as settled
    await db.transactions.update_one(
        {"transaction_id": transaction_id},
        {
            "$set": {
                "settled": True,
                "settlement_status": "completed",
                "settled_at": now.isoformat(),
                "settled_by": user["user_id"],
                "settled_by_name": user["name"],
                "settlement_destination_id": dest_account_id,
                "settlement_destination_name": dest["account_name"],
                "psp_actual_amount_received": settle_amount,
                "psp_settlement_variance": variance,
            }
        },
    )

    # Update PSP stats
    if psp:
        commission_amount = tx.get("psp_commission_amount", 0)
        await db.psps.update_one(
            {"psp_id": tx.get("psp_id")},
            {
                "$inc": {
                    "total_volume": tx.get("amount", 0),
                    "total_commission": commission_amount,
                    "pending_settlement": -expected_amount,
                }
            },
        )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


# Legacy endpoint - Mark single PSP transaction as settled (immediate)
@api_router.post("/psp/transactions/{transaction_id}/settle")
async def settle_psp_transaction(
    transaction_id: str,
    destination_account_id: Optional[str] = None,
    user: dict = Depends(require_accountant_or_admin),
):
    """Mark a single PSP transaction as settled and transfer to treasury (immediate settlement)"""
    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.get("destination_type") != "psp":
        raise HTTPException(
            status_code=400, detail="Transaction is not a PSP transaction"
        )

    if tx.get("settled"):
        raise HTTPException(status_code=400, detail="Transaction already settled")

    if tx.get("status") not in [
        TransactionStatus.APPROVED,
        TransactionStatus.COMPLETED,
        TransactionStatus.PENDING,
    ]:
        raise HTTPException(
            status_code=400, detail="Transaction cannot be settled in current status"
        )

    now = datetime.now(timezone.utc)

    # Get PSP info for destination
    psp = await db.psps.find_one({"psp_id": tx.get("psp_id")}, {"_id": 0})
    dest_account_id = destination_account_id or (
        psp.get("settlement_destination_id") if psp else None
    )

    if not dest_account_id:
        raise HTTPException(status_code=400, detail="No destination account specified")

    # Get destination account
    dest = await db.treasury_accounts.find_one(
        {"account_id": dest_account_id}, {"_id": 0}
    )
    if not dest:
        raise HTTPException(
            status_code=404, detail="Destination treasury account not found"
        )

    # Amount to settle (net amount after commission)
    settle_amount = tx.get("psp_net_amount", tx.get("amount", 0))

    # Currency conversion: convert from transaction currency to treasury account currency
    tx_currency = tx.get("currency", "USD")
    dest_currency = dest.get("currency", "USD")
    treasury_amount = convert_currency(settle_amount, tx_currency, dest_currency)

    # Update treasury balance (in treasury account's currency)
    await db.treasury_accounts.update_one(
        {"account_id": dest_account_id},
        {"$inc": {"balance": treasury_amount}, "$set": {"updated_at": now.isoformat()}},
    )

    # Add treasury transaction record
    treasury_tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
    conversion_note = (
        f" (Converted: {tx_currency} {settle_amount:,.2f} -> {dest_currency} {treasury_amount:,.2f})"
        if tx_currency != dest_currency
        else ""
    )
    treasury_tx = {
        "treasury_transaction_id": treasury_tx_id,
        "account_id": dest_account_id,
        "account_name": dest["account_name"],
        "transaction_type": "psp_settlement",
        "amount": treasury_amount,
        "currency": dest_currency,
        "original_amount": settle_amount,
        "original_currency": tx_currency,
        "reference": f"PSP Settlement - {tx.get('reference', transaction_id)}",
        "description": f"Settlement from {tx.get('psp_name', 'PSP')}{conversion_note}",
        "related_transaction_id": transaction_id,
        "psp_id": tx.get("psp_id"),
        "psp_name": tx.get("psp_name"),
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.treasury_transactions.insert_one(treasury_tx)

    # Mark transaction as settled
    await db.transactions.update_one(
        {"transaction_id": transaction_id},
        {
            "$set": {
                "settled": True,
                "settlement_status": "completed",
                "settled_at": now.isoformat(),
                "settled_by": user["user_id"],
                "settled_by_name": user["name"],
                "settlement_destination_id": dest_account_id,
                "settlement_destination_name": dest["account_name"],
            }
        },
    )

    # Update PSP stats
    if psp:
        commission_amount = tx.get("psp_commission_amount", 0)
        await db.psps.update_one(
            {"psp_id": tx.get("psp_id")},
            {
                "$inc": {
                    "total_volume": tx.get("amount", 0),
                    "total_commission": commission_amount,
                    "pending_settlement": -settle_amount,
                }
            },
        )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


# ============== RESERVE FUND MANAGEMENT ==============


@api_router.get("/psps/{psp_id}/reserve-funds")
async def get_psp_reserve_funds(psp_id: str, user: dict = Depends(get_current_user)):
    """Get reserve fund ledger for a PSP — all transactions with reserve fund amounts."""
    psp = await db.psps.find_one({"psp_id": psp_id}, {"_id": 0})
    if not psp:
        raise HTTPException(status_code=404, detail="PSP not found")

    holding_days = psp.get("holding_days", 0)
    now = datetime.now(timezone.utc)

    # Get all PSP transactions that have reserve fund amounts
    txs = (
        await db.transactions.find(
            {
                "psp_id": psp_id,
                "destination_type": "psp",
                "status": {
                    "$in": [
                        TransactionStatus.PENDING,
                        TransactionStatus.APPROVED,
                        TransactionStatus.COMPLETED,
                    ]
                },
                "$or": [
                    {"psp_reserve_fund_amount": {"$gt": 0}},
                    {"psp_chargeback_amount": {"$gt": 0}},
                    {"settled": True},
                ],
            },
            {"_id": 0},
        )
        .sort("created_at", -1)
        .to_list(10000)
    )

    reserve_fund_rate = (
        psp.get("reserve_fund_rate", psp.get("chargeback_rate", 0)) / 100
    )

    ledger = []
    total_held = 0
    total_released = 0
    due_this_week = 0

    for tx in txs:
        rf_amount = tx.get(
            "psp_reserve_fund_amount", tx.get("psp_chargeback_amount", 0)
        )
        if rf_amount <= 0:
            rf_amount = round(tx.get("amount", 0) * reserve_fund_rate, 2)
        if rf_amount <= 0:
            continue

        # Calculate dates
        created_str = tx.get("created_at", "")
        try:
            created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
        except:
            created_dt = now

        release_date = (
            created_dt + timedelta(days=holding_days)
            if holding_days > 0
            else created_dt
        )
        days_remaining = max(0, (release_date - now).days)
        is_released = tx.get("reserve_fund_released", False)

        # Determine status
        if is_released:
            status = "released"
            total_released += rf_amount
        elif release_date <= now:
            status = "due"
            total_held += rf_amount
            if (release_date - now).days >= -7:
                due_this_week += rf_amount
        else:
            status = "held"
            total_held += rf_amount
            if days_remaining <= 7:
                due_this_week += rf_amount

        ledger.append(
            {
                "transaction_id": tx["transaction_id"],
                "reference": tx.get("reference", tx["transaction_id"]),
                "client_name": tx.get("client_name", ""),
                "amount": tx.get("amount", 0),
                "currency": tx.get("currency", "USD"),
                "reserve_fund_amount": rf_amount,
                "hold_date": created_dt.isoformat(),
                "release_date": release_date.isoformat(),
                "days_remaining": days_remaining,
                "status": status,
                "released_at": tx.get("reserve_fund_released_at"),
                "released_by_name": tx.get("reserve_fund_released_by_name"),
            }
        )

    return {
        "ledger": ledger,
        "summary": {
            "total_held": round(total_held, 2),
            "total_released": round(total_released, 2),
            "due_this_week": round(due_this_week, 2),
            "holding_days": holding_days,
            "reserve_fund_rate": psp.get(
                "reserve_fund_rate", psp.get("chargeback_rate", 0)
            ),
            "total_entries": len(ledger),
        },
    }


@api_router.post("/psps/reserve-funds/{transaction_id}/release")
async def release_reserve_fund(
    transaction_id: str, user: dict = Depends(require_admin)
):
    """Mark a reserve fund as released back."""
    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if tx.get("reserve_fund_released"):
        raise HTTPException(status_code=400, detail="Reserve fund already released")

    now = datetime.now(timezone.utc)
    rf_amount = tx.get("psp_reserve_fund_amount", tx.get("psp_chargeback_amount", 0))

    # Fall back to calculating from PSP rate if amount not stored (legacy transactions)
    if not rf_amount or rf_amount <= 0:
        psp = await db.psps.find_one({"psp_id": tx.get("psp_id")}, {"_id": 0})
        if psp:
            rf_rate = psp.get("reserve_fund_rate", psp.get("chargeback_rate", 0)) / 100
            rf_amount = round(tx.get("amount", 0) * rf_rate, 2)

    await db.transactions.update_one(
        {"transaction_id": transaction_id},
        {
            "$set": {
                "reserve_fund_released": True,
                "reserve_fund_released_at": now.isoformat(),
                "reserve_fund_released_by": user["user_id"],
                "reserve_fund_released_by_name": user["name"],
            }
        },
    )

    # Credit the reserve fund back to treasury
    psp = await db.psps.find_one({"psp_id": tx.get("psp_id")}, {"_id": 0})
    if psp and psp.get("settlement_destination_id") and rf_amount > 0:
        dest = await db.treasury_accounts.find_one(
            {"account_id": psp["settlement_destination_id"]}, {"_id": 0}
        )
        tx_currency = tx.get("currency", "USD")
        dest_currency = dest.get("currency", "USD") if dest else "USD"
        treasury_amount = convert_currency(rf_amount, tx_currency, dest_currency)

        await db.treasury_accounts.update_one(
            {"account_id": psp["settlement_destination_id"]},
            {
                "$inc": {"balance": treasury_amount},
                "$set": {"updated_at": now.isoformat()},
            },
        )
        conversion_note = (
            f" (Converted: {tx_currency} {rf_amount:,.2f} -> {dest_currency} {treasury_amount:,.2f})"
            if tx_currency != dest_currency
            else ""
        )
        # Create treasury transaction record
        await db.treasury_transactions.insert_one(
            {
                "treasury_transaction_id": f"ttx_{uuid.uuid4().hex[:12]}",
                "account_id": psp["settlement_destination_id"],
                "account_name": dest["account_name"] if dest else None,
                "transaction_type": "reserve_fund_release",
                "amount": treasury_amount,
                "currency": dest_currency,
                "original_amount": rf_amount,
                "original_currency": tx_currency,
                "description": f"Reserve fund release - {tx.get('reference', transaction_id)} from {psp.get('psp_name', '')}{conversion_note}",
                "reference": f"RF-{transaction_id}",
                "related_transaction_id": transaction_id,
                "psp_id": tx.get("psp_id"),
                "psp_name": psp.get("psp_name"),
                "created_at": now.isoformat(),
                "created_by": user["user_id"],
                "created_by_name": user["name"],
            }
        )

    return {
        "message": "Reserve fund released",
        "amount": rf_amount,
        "transaction_id": transaction_id,
    }


@api_router.post("/psps/reserve-funds/bulk-release")
async def bulk_release_reserve_funds(
    request: Request, user: dict = Depends(require_admin)
):
    """Bulk release multiple reserve funds."""
    data = await request.json()
    tx_ids = data.get("transaction_ids", [])
    if not tx_ids:
        raise HTTPException(status_code=400, detail="No transaction IDs provided")

    now = datetime.now(timezone.utc)
    released_count = 0
    total_released = 0

    for tx_id in tx_ids:
        tx = await db.transactions.find_one(
            {"transaction_id": tx_id, "reserve_fund_released": {"$ne": True}},
            {"_id": 0},
        )
        if not tx:
            continue
        rf_amount = tx.get(
            "psp_reserve_fund_amount", tx.get("psp_chargeback_amount", 0)
        )
        # Fall back to calculating from PSP rate if amount not stored (legacy transactions)
        if not rf_amount or rf_amount <= 0:
            psp_for_rate = await db.psps.find_one(
                {"psp_id": tx.get("psp_id")}, {"_id": 0}
            )
            if psp_for_rate:
                rf_rate = (
                    psp_for_rate.get(
                        "reserve_fund_rate", psp_for_rate.get("chargeback_rate", 0)
                    )
                    / 100
                )
                rf_amount = round(tx.get("amount", 0) * rf_rate, 2)
        if rf_amount <= 0:
            continue

        await db.transactions.update_one(
            {"transaction_id": tx_id},
            {
                "$set": {
                    "reserve_fund_released": True,
                    "reserve_fund_released_at": now.isoformat(),
                    "reserve_fund_released_by": user["user_id"],
                    "reserve_fund_released_by_name": user["name"],
                }
            },
        )

        psp = await db.psps.find_one({"psp_id": tx.get("psp_id")}, {"_id": 0})
        if psp and psp.get("settlement_destination_id"):
            dest = await db.treasury_accounts.find_one(
                {"account_id": psp["settlement_destination_id"]}, {"_id": 0}
            )
            tx_currency = tx.get("currency", "USD")
            dest_currency = dest.get("currency", "USD") if dest else "USD"
            treasury_amount = convert_currency(rf_amount, tx_currency, dest_currency)

            await db.treasury_accounts.update_one(
                {"account_id": psp["settlement_destination_id"]},
                {
                    "$inc": {"balance": treasury_amount},
                    "$set": {"updated_at": now.isoformat()},
                },
            )
            conversion_note = (
                f" (Converted: {tx_currency} {rf_amount:,.2f} -> {dest_currency} {treasury_amount:,.2f})"
                if tx_currency != dest_currency
                else ""
            )
            await db.treasury_transactions.insert_one(
                {
                    "treasury_transaction_id": f"ttx_{uuid.uuid4().hex[:12]}",
                    "account_id": psp["settlement_destination_id"],
                    "account_name": dest["account_name"] if dest else None,
                    "transaction_type": "reserve_fund_release",
                    "amount": treasury_amount,
                    "currency": dest_currency,
                    "original_amount": rf_amount,
                    "original_currency": tx_currency,
                    "description": f"Reserve fund release - {tx.get('reference', tx_id)} from {psp.get('psp_name', '')}{conversion_note}",
                    "reference": f"RF-{tx_id}",
                    "related_transaction_id": tx_id,
                    "psp_id": tx.get("psp_id"),
                    "psp_name": psp.get("psp_name"),
                    "created_at": now.isoformat(),
                    "created_by": user["user_id"],
                    "created_by_name": user["name"],
                }
            )

        released_count += 1
        total_released += rf_amount

    return {
        "message": f"Released {released_count} reserve funds",
        "total_released": round(total_released, 2),
        "count": released_count,
    }


@api_router.get("/psps/reserve-funds/global-summary")
async def get_global_reserve_fund_summary(user: dict = Depends(get_current_user)):
    """Get global reserve fund summary across all PSPs."""
    psps = await db.psps.find(
        {"status": PSPStatus.ACTIVE},
        {
            "_id": 0,
            "psp_id": 1,
            "psp_name": 1,
            "reserve_fund_rate": 1,
            "chargeback_rate": 1,
            "holding_days": 1,
        },
    ).to_list(1000)
    now = datetime.now(timezone.utc)

    total_held = 0
    total_released = 0
    due_for_release = 0

    for psp in psps:
        rf_rate = psp.get("reserve_fund_rate", psp.get("chargeback_rate", 0)) / 100
        holding = psp.get("holding_days", 0)

        txs = await db.transactions.find(
            {
                "psp_id": psp["psp_id"],
                "destination_type": "psp",
                "$or": [
                    {"psp_reserve_fund_amount": {"$gt": 0}},
                    {"psp_chargeback_amount": {"$gt": 0}},
                ],
            },
            {
                "_id": 0,
                "psp_reserve_fund_amount": 1,
                "psp_chargeback_amount": 1,
                "reserve_fund_released": 1,
                "created_at": 1,
                "amount": 1,
            },
        ).to_list(10000)

        for tx in txs:
            rf = tx.get("psp_reserve_fund_amount", tx.get("psp_chargeback_amount", 0))
            if rf <= 0:
                rf = round(tx.get("amount", 0) * rf_rate, 2)
            if rf <= 0:
                continue

            if tx.get("reserve_fund_released"):
                total_released += rf
            else:
                total_held += rf
                try:
                    created = datetime.fromisoformat(
                        tx.get("created_at", "").replace("Z", "+00:00")
                    )
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    release_dt = created + timedelta(days=holding)
                    if release_dt <= now:
                        due_for_release += rf
                except:
                    pass

    return {
        "total_held": round(total_held, 2),
        "total_released": round(total_released, 2),
        "due_for_release": round(due_for_release, 2),
    }


# ============== VENDOR ROUTES ==============


@api_router.get("/vendors")
async def get_vendors(user: dict = Depends(get_current_user)):
    vendors = await db.vendors.find({}, {"_id": 0}).to_list(1000)

    # Batch fetch treasury accounts to avoid N+1 queries
    treasury_ids = list(
        set(
            v.get("settlement_destination_id")
            for v in vendors
            if v.get("settlement_destination_id")
        )
    )
    treasury_map = {}
    if treasury_ids:
        treasuries = await db.treasury_accounts.find(
            {"account_id": {"$in": treasury_ids}}, {"_id": 0}
        ).to_list(len(treasury_ids))
        treasury_map = {t["account_id"]: t for t in treasuries}

    # Batch fetch all pending transactions for all vendors
    vendor_ids = [v["vendor_id"] for v in vendors]
    pending_txs_all = await db.transactions.find(
        {
            "vendor_id": {"$in": vendor_ids},
            "destination_type": "vendor",
            "status": {
                "$in": [TransactionStatus.APPROVED, TransactionStatus.COMPLETED]
            },
            "settled": {"$ne": True},
        },
        {"_id": 0},
    ).to_list(10000)

    # Batch fetch all completed income/expense entries for all vendors
    ie_entries_all = await db.income_expenses.find(
        {
            "vendor_id": {"$in": vendor_ids},
            "status": "completed",
            "settled": {"$ne": True},
        },
        {"_id": 0},
    ).to_list(10000)

    # Group transactions and IE entries by vendor_id
    from collections import defaultdict

    pending_by_vendor = defaultdict(list)
    for tx in pending_txs_all:
        pending_by_vendor[tx["vendor_id"]].append(tx)

    ie_by_vendor = defaultdict(list)
    for ie in ie_entries_all:
        ie_by_vendor[ie["vendor_id"]].append(ie)

    # Populate vendor data
    for vendor in vendors:
        if vendor.get("settlement_destination_id"):
            dest = treasury_map.get(vendor["settlement_destination_id"])
            vendor["settlement_destination_name"] = (
                dest["account_name"] if dest else "Unknown"
            )
            vendor["settlement_destination_bank"] = (
                dest.get("bank_name") if dest else None
            )

        pending_txs = pending_by_vendor.get(vendor["vendor_id"], [])
        vendor["pending_transactions_count"] = len(pending_txs)

        # Calculate net pending amount by currency
        currency_breakdown = {}

        def ensure_currency(currency):
            if currency not in currency_breakdown:
                currency_breakdown[currency] = {
                    "deposits_base": 0,
                    "withdrawals_base": 0,
                    "deposits_usd": 0,
                    "withdrawals_usd": 0,
                    "commission_base": 0,
                    "commission_usd": 0,
                }

        for tx in pending_txs:
            currency = tx.get("base_currency") or tx.get("currency", "USD")
            ensure_currency(currency)

            base_amount = tx.get("base_amount") or tx.get("amount", 0)
            usd_amount = tx.get("amount", 0)
            commission_base = tx.get("vendor_commission_base_amount", 0)
            commission_usd = tx.get("vendor_commission_amount", 0)

            if tx.get("transaction_type") == "deposit":
                currency_breakdown[currency]["deposits_base"] += base_amount
                currency_breakdown[currency]["deposits_usd"] += usd_amount
            else:
                currency_breakdown[currency]["withdrawals_base"] += base_amount
                currency_breakdown[currency]["withdrawals_usd"] += usd_amount

            currency_breakdown[currency]["commission_base"] += commission_base
            currency_breakdown[currency]["commission_usd"] += commission_usd

        # Include income/expense entries: income = Money In, expense = Money Out
        for ie in ie_by_vendor.get(vendor["vendor_id"], []):
            currency = ie.get("currency", "USD")
            ensure_currency(currency)

            base_amount = ie.get("amount", 0)
            usd_amount = ie.get("amount_usd") or base_amount
            commission_base = ie.get("vendor_commission_base_amount", 0)
            commission_usd = ie.get("vendor_commission_amount", 0)

            if ie.get("entry_type") == "income":
                currency_breakdown[currency]["deposits_base"] += base_amount
                currency_breakdown[currency]["deposits_usd"] += usd_amount
            else:
                currency_breakdown[currency]["withdrawals_base"] += base_amount
                currency_breakdown[currency]["withdrawals_usd"] += usd_amount

            currency_breakdown[currency]["commission_base"] += commission_base
            currency_breakdown[currency]["commission_usd"] += commission_usd

        # Build settlement by currency for list view
        settlement_by_currency = []
        total_net_usd = 0
        for currency, data in currency_breakdown.items():
            net_base = (data["deposits_base"] - data["withdrawals_base"]) - data[
                "commission_base"
            ]
            net_usd = (data["deposits_usd"] - data["withdrawals_usd"]) - data[
                "commission_usd"
            ]
            total_net_usd += net_usd
            settlement_by_currency.append(
                {
                    "currency": currency,
                    "amount": net_base,
                    "usd_equivalent": net_usd,
                    "commission_base": data["commission_base"],
                }
            )

        vendor["settlement_by_currency"] = settlement_by_currency
        vendor["pending_amount"] = total_net_usd

    return vendors


@api_router.get("/vendors/{vendor_id}")
async def get_vendor(vendor_id: str, user: dict = Depends(get_current_user)):
    vendor = await db.vendors.find_one({"vendor_id": vendor_id}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    # Calculate settlement balance by currency (unsettled approved/completed transactions)
    # Settlement = (Money In - Money Out - Commission)
    # Money In = deposits + income, Money Out = withdrawals + expense
    settlement_pipeline = [
        {
            "$match": {
                "vendor_id": vendor_id,
                "status": {"$in": ["approved", "completed"]},
                "settled": {"$ne": True},
            }
        },
        {
            "$group": {
                "_id": {"$ifNull": ["$base_currency", "$currency"]},
                "deposit_amount": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$transaction_type", "deposit"]},
                            {"$ifNull": ["$base_amount", "$amount"]},
                            0,
                        ]
                    }
                },
                "withdrawal_amount": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$transaction_type", "withdrawal"]},
                            {"$ifNull": ["$base_amount", "$amount"]},
                            0,
                        ]
                    }
                },
                "deposit_usd": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$transaction_type", "deposit"]},
                            "$amount",
                            0,
                        ]
                    }
                },
                "withdrawal_usd": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$transaction_type", "withdrawal"]},
                            "$amount",
                            0,
                        ]
                    }
                },
                "deposit_count": {
                    "$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]}, 1, 0]}
                },
                "withdrawal_count": {
                    "$sum": {
                        "$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, 1, 0]
                    }
                },
                "total_commission_usd": {
                    "$sum": {"$ifNull": ["$vendor_commission_amount", 0]}
                },
                "total_commission_base": {
                    "$sum": {"$ifNull": ["$vendor_commission_base_amount", 0]}
                },
            }
        },
    ]

    settlement_by_currency = await db.transactions.aggregate(
        settlement_pipeline
    ).to_list(100)

    # Also fetch completed income/expense entries for this vendor
    ie_pipeline = [
        {
            "$match": {
                "vendor_id": vendor_id,
                "status": "completed",
                "settled": {"$ne": True},
            }
        },
        {
            "$group": {
                "_id": "$currency",
                "income_base": {
                    "$sum": {
                        "$cond": [{"$eq": ["$entry_type", "income"]}, "$amount", 0]
                    }
                },
                "expense_base": {
                    "$sum": {
                        "$cond": [{"$eq": ["$entry_type", "expense"]}, "$amount", 0]
                    }
                },
                "income_usd": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$entry_type", "income"]},
                            {"$ifNull": ["$amount_usd", "$amount"]},
                            0,
                        ]
                    }
                },
                "expense_usd": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$entry_type", "expense"]},
                            {"$ifNull": ["$amount_usd", "$amount"]},
                            0,
                        ]
                    }
                },
                "income_count": {
                    "$sum": {"$cond": [{"$eq": ["$entry_type", "income"]}, 1, 0]}
                },
                "expense_count": {
                    "$sum": {"$cond": [{"$eq": ["$entry_type", "expense"]}, 1, 0]}
                },
                "ie_commission_usd": {
                    "$sum": {"$ifNull": ["$vendor_commission_amount", 0]}
                },
                "ie_commission_base": {
                    "$sum": {"$ifNull": ["$vendor_commission_base_amount", 0]}
                },
            }
        },
    ]
    ie_by_currency = await db.income_expenses.aggregate(ie_pipeline).to_list(100)
    ie_map = {item["_id"] or "USD": item for item in ie_by_currency}

    # Merge transactions and IE data into settlement_by_currency
    currency_data = {}
    for item in settlement_by_currency:
        curr = item["_id"] or "USD"
        currency_data[curr] = {
            "deposit_amount": item["deposit_amount"],
            "withdrawal_amount": item["withdrawal_amount"],
            "deposit_usd": item["deposit_usd"],
            "withdrawal_usd": item["withdrawal_usd"],
            "deposit_count": item["deposit_count"],
            "withdrawal_count": item["withdrawal_count"],
            "commission_usd": item["total_commission_usd"],
            "commission_base": item["total_commission_base"],
        }

    for curr, ie_item in ie_map.items():
        if curr not in currency_data:
            currency_data[curr] = {
                "deposit_amount": 0,
                "withdrawal_amount": 0,
                "deposit_usd": 0,
                "withdrawal_usd": 0,
                "deposit_count": 0,
                "withdrawal_count": 0,
                "commission_usd": 0,
                "commission_base": 0,
            }
        # Income = Money In (like deposits), Expense = Money Out (like withdrawals)
        currency_data[curr]["deposit_amount"] += ie_item["income_base"]
        currency_data[curr]["deposit_usd"] += ie_item["income_usd"]
        currency_data[curr]["deposit_count"] += ie_item["income_count"]
        currency_data[curr]["withdrawal_amount"] += ie_item["expense_base"]
        currency_data[curr]["withdrawal_usd"] += ie_item["expense_usd"]
        currency_data[curr]["withdrawal_count"] += ie_item["expense_count"]
        currency_data[curr]["commission_usd"] += ie_item["ie_commission_usd"]
        currency_data[curr]["commission_base"] += ie_item["ie_commission_base"]

    vendor["settlement_by_currency"] = [
        {
            "currency": curr,
            "amount": (d["deposit_amount"] - d["withdrawal_amount"])
            - d["commission_base"],
            "usd_equivalent": (d["deposit_usd"] - d["withdrawal_usd"])
            - d["commission_usd"],
            "deposit_amount": d["deposit_amount"],
            "withdrawal_amount": d["withdrawal_amount"],
            "commission_earned_usd": d["commission_usd"],
            "commission_earned_base": d["commission_base"],
            "deposit_count": d["deposit_count"],
            "withdrawal_count": d["withdrawal_count"],
            "transaction_count": d["deposit_count"] + d["withdrawal_count"],
        }
        for curr, d in currency_data.items()
    ]

    return vendor


@api_router.post("/vendors")
async def create_vendor(
    vendor_data: VendorCreate, user: dict = Depends(require_accountant_or_admin)
):
    # Check if email already exists
    existing = await db.users.find_one({"email": vendor_data.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    vendor_id = f"vendor_{uuid.uuid4().hex[:12]}"
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # Create user account for vendor
    user_doc = {
        "user_id": user_id,
        "email": vendor_data.email,
        "password_hash": hash_password(vendor_data.password),
        "name": vendor_data.vendor_name,
        "role": UserRole.VENDOR,
        "vendor_id": vendor_id,  # Link to vendor
        "picture": None,
        "is_active": True,
        "created_at": now.isoformat(),
    }
    await db.users.insert_one(user_doc)

    # Create vendor record
    vendor_doc = {
        "vendor_id": vendor_id,
        "user_id": user_id,
        "vendor_name": vendor_data.vendor_name,
        "email": vendor_data.email,
        "deposit_commission": vendor_data.deposit_commission,
        "withdrawal_commission": vendor_data.withdrawal_commission,
        "description": vendor_data.description,
        "total_volume": 0.0,
        "total_commission": 0.0,
        "pending_settlement": 0.0,
        "status": VendorStatus.ACTIVE,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    await db.vendors.insert_one(vendor_doc)
    return await db.vendors.find_one({"vendor_id": vendor_id}, {"_id": 0})


@api_router.put("/vendors/{vendor_id}")
async def update_vendor(
    vendor_id: str,
    update_data: VendorUpdate,
    user: dict = Depends(require_accountant_or_admin),
):
    updates = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    result = await db.vendors.update_one({"vendor_id": vendor_id}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vendor not found")

    # Update vendor name in user record if changed
    if updates.get("vendor_name"):
        vendor = await db.vendors.find_one({"vendor_id": vendor_id}, {"_id": 0})
        if vendor:
            await db.users.update_one(
                {"user_id": vendor["user_id"]},
                {"$set": {"name": updates["vendor_name"]}},
            )

    return await db.vendors.find_one({"vendor_id": vendor_id}, {"_id": 0})


@api_router.delete("/vendors/{vendor_id}")
async def delete_vendor(
    vendor_id: str, user: dict = Depends(require_accountant_or_admin)
):
    vendor = await db.vendors.find_one({"vendor_id": vendor_id}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    # Delete vendor user account
    await db.users.delete_one({"user_id": vendor["user_id"]})

    # Delete vendor record
    await db.vendors.delete_one({"vendor_id": vendor_id})

    return {"message": "Vendor deleted"}


# Get vendor's assigned transactions (for vendor portal)
@api_router.get("/vendors/{vendor_id}/transactions")
async def get_vendor_transactions(
    vendor_id: str, status: Optional[str] = None, user: dict = Depends(get_current_user)
):
    # Vendors can only see their own transactions
    if user.get("role") == UserRole.VENDOR:
        user_vendor = await db.vendors.find_one(
            {"user_id": user["user_id"]}, {"_id": 0}
        )
        if not user_vendor or user_vendor["vendor_id"] != vendor_id:
            raise HTTPException(status_code=403, detail="Access denied")

    query = {"vendor_id": vendor_id, "destination_type": "vendor"}
    if status:
        query["status"] = status

    transactions = (
        await db.transactions.find(query, {"_id": 0})
        .sort("created_at", -1)
        .to_list(1000)
    )
    return transactions


# Get current vendor info (for logged in vendor)
@api_router.get("/vendor/me")
async def get_my_vendor_info(user: dict = Depends(require_vendor)):
    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    # Get pending transactions
    pending_txs = await db.transactions.find(
        {
            "vendor_id": vendor["vendor_id"],
            "destination_type": "vendor",
            "status": TransactionStatus.PENDING,
        },
        {"_id": 0},
    ).to_list(1000)

    vendor["pending_transactions"] = pending_txs
    vendor["pending_count"] = len(pending_txs)

    # Calculate settlement balance by currency (unsettled approved/completed transactions)
    # Settlement = (Money In - Money Out - Commission)
    # Money In = deposits + income, Money Out = withdrawals + expense
    settlement_pipeline = [
        {
            "$match": {
                "vendor_id": vendor["vendor_id"],
                "status": {"$in": ["approved", "completed"]},
                "settled": {"$ne": True},
            }
        },
        {
            "$group": {
                "_id": {"$ifNull": ["$base_currency", "$currency"]},
                "deposit_amount": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$transaction_type", "deposit"]},
                            {"$ifNull": ["$base_amount", "$amount"]},
                            0,
                        ]
                    }
                },
                "withdrawal_amount": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$transaction_type", "withdrawal"]},
                            {"$ifNull": ["$base_amount", "$amount"]},
                            0,
                        ]
                    }
                },
                "deposit_usd": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$transaction_type", "deposit"]},
                            "$amount",
                            0,
                        ]
                    }
                },
                "withdrawal_usd": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$transaction_type", "withdrawal"]},
                            "$amount",
                            0,
                        ]
                    }
                },
                "total_commission_usd": {
                    "$sum": {"$ifNull": ["$vendor_commission_amount", 0]}
                },
                "total_commission_base": {
                    "$sum": {"$ifNull": ["$vendor_commission_base_amount", 0]}
                },
                "deposit_count": {
                    "$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]}, 1, 0]}
                },
                "withdrawal_count": {
                    "$sum": {
                        "$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, 1, 0]
                    }
                },
            }
        },
    ]

    settlement_by_currency = await db.transactions.aggregate(
        settlement_pipeline
    ).to_list(100)

    # Also fetch completed income/expense entries for this vendor
    ie_pipeline = [
        {
            "$match": {
                "vendor_id": vendor["vendor_id"],
                "status": "completed",
                "settled": {"$ne": True},
            }
        },
        {
            "$group": {
                "_id": "$currency",
                "income_base": {
                    "$sum": {
                        "$cond": [{"$eq": ["$entry_type", "income"]}, "$amount", 0]
                    }
                },
                "expense_base": {
                    "$sum": {
                        "$cond": [{"$eq": ["$entry_type", "expense"]}, "$amount", 0]
                    }
                },
                "income_usd": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$entry_type", "income"]},
                            {"$ifNull": ["$amount_usd", "$amount"]},
                            0,
                        ]
                    }
                },
                "expense_usd": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$entry_type", "expense"]},
                            {"$ifNull": ["$amount_usd", "$amount"]},
                            0,
                        ]
                    }
                },
                "income_count": {
                    "$sum": {"$cond": [{"$eq": ["$entry_type", "income"]}, 1, 0]}
                },
                "expense_count": {
                    "$sum": {"$cond": [{"$eq": ["$entry_type", "expense"]}, 1, 0]}
                },
                "ie_commission_usd": {
                    "$sum": {"$ifNull": ["$vendor_commission_amount", 0]}
                },
                "ie_commission_base": {
                    "$sum": {"$ifNull": ["$vendor_commission_base_amount", 0]}
                },
            }
        },
    ]
    ie_by_currency = await db.income_expenses.aggregate(ie_pipeline).to_list(100)
    ie_map = {item["_id"] or "USD": item for item in ie_by_currency}

    # Merge transactions and IE data
    currency_data = {}
    for item in settlement_by_currency:
        curr = item["_id"] or "USD"
        currency_data[curr] = {
            "deposit_amount": item["deposit_amount"],
            "withdrawal_amount": item["withdrawal_amount"],
            "deposit_usd": item["deposit_usd"],
            "withdrawal_usd": item["withdrawal_usd"],
            "deposit_count": item["deposit_count"],
            "withdrawal_count": item["withdrawal_count"],
            "commission_usd": item["total_commission_usd"],
            "commission_base": item["total_commission_base"],
        }

    for curr, ie_item in ie_map.items():
        if curr not in currency_data:
            currency_data[curr] = {
                "deposit_amount": 0,
                "withdrawal_amount": 0,
                "deposit_usd": 0,
                "withdrawal_usd": 0,
                "deposit_count": 0,
                "withdrawal_count": 0,
                "commission_usd": 0,
                "commission_base": 0,
            }
        currency_data[curr]["deposit_amount"] += ie_item["income_base"]
        currency_data[curr]["deposit_usd"] += ie_item["income_usd"]
        currency_data[curr]["deposit_count"] += ie_item["income_count"]
        currency_data[curr]["withdrawal_amount"] += ie_item["expense_base"]
        currency_data[curr]["withdrawal_usd"] += ie_item["expense_usd"]
        currency_data[curr]["withdrawal_count"] += ie_item["expense_count"]
        currency_data[curr]["commission_usd"] += ie_item["ie_commission_usd"]
        currency_data[curr]["commission_base"] += ie_item["ie_commission_base"]

    vendor["settlement_by_currency"] = [
        {
            "currency": curr,
            "amount": (d["deposit_amount"] - d["withdrawal_amount"])
            - d["commission_base"],
            "usd_equivalent": (d["deposit_usd"] - d["withdrawal_usd"])
            - d["commission_usd"],
            "deposit_amount": d["deposit_amount"],
            "withdrawal_amount": d["withdrawal_amount"],
            "commission_earned_usd": d["commission_usd"],
            "commission_earned_base": d["commission_base"],
            "deposit_count": d["deposit_count"],
            "withdrawal_count": d["withdrawal_count"],
            "transaction_count": d["deposit_count"] + d["withdrawal_count"],
        }
        for curr, d in currency_data.items()
    ]

    return vendor


# Vendor approve transaction
@api_router.post("/vendor/transactions/{transaction_id}/approve")
async def vendor_approve_transaction(
    transaction_id: str, user: dict = Depends(require_vendor)
):
    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.get("vendor_id") != vendor["vendor_id"]:
        raise HTTPException(
            status_code=403, detail="Transaction does not belong to this vendor"
        )

    if tx["status"] != TransactionStatus.PENDING:
        raise HTTPException(status_code=400, detail="Transaction is not pending")

    # Only withdrawals require proof upload before approving
    # Deposits can be approved without proof
    if tx["transaction_type"] == TransactionType.WITHDRAWAL and not tx.get(
        "vendor_proof_image"
    ):
        raise HTTPException(
            status_code=400,
            detail="Please upload proof screenshot before approving withdrawal",
        )

    now = datetime.now(timezone.utc)

    # Calculate commission based on transaction type and mode
    tx_mode = tx.get("transaction_mode", "bank")
    commission_rate = 0.0
    if tx["transaction_type"] == TransactionType.DEPOSIT:
        if tx_mode == "cash":
            commission_rate = (
                vendor.get(
                    "deposit_commission_cash", vendor.get("deposit_commission", 0)
                )
                / 100
            )
        else:
            commission_rate = vendor.get("deposit_commission", 0) / 100
    elif tx["transaction_type"] == TransactionType.WITHDRAWAL:
        if tx_mode == "cash":
            commission_rate = (
                vendor.get(
                    "withdrawal_commission_cash", vendor.get("withdrawal_commission", 0)
                )
                / 100
            )
        else:
            commission_rate = vendor.get("withdrawal_commission", 0) / 100

    # Calculate commission on the USD amount
    commission_amount_usd = round(tx["amount"] * commission_rate, 2)

    # Calculate commission in base currency (original currency)
    base_amount = tx.get("base_amount") or tx["amount"]
    base_currency = tx.get("base_currency") or tx.get("currency", "USD")
    commission_amount_base = round(base_amount * commission_rate, 2)

    updates = {
        "status": TransactionStatus.APPROVED,
        "processed_by": user["user_id"],
        "processed_by_name": user["name"],
        "processed_at": now.isoformat(),
        "vendor_commission_rate": commission_rate * 100,  # Store as percentage
        "vendor_commission_amount": commission_amount_usd,  # USD amount
        "vendor_commission_base_amount": commission_amount_base,  # Base currency amount
        "vendor_commission_base_currency": base_currency,  # Base currency code
    }

    await db.transactions.update_one(
        {"transaction_id": transaction_id}, {"$set": updates}
    )

    # Update vendor's total commission and volume
    await db.vendors.update_one(
        {"vendor_id": vendor["vendor_id"]},
        {
            "$inc": {
                "total_commission": commission_amount_usd,
                "total_volume": tx["amount"],
            },
            "$set": {"updated_at": now.isoformat()},
        },
    )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


# Vendor reject transaction
@api_router.post("/vendor/transactions/{transaction_id}/reject")
async def vendor_reject_transaction(
    transaction_id: str, reason: str = "", user: dict = Depends(require_vendor)
):
    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.get("vendor_id") != vendor["vendor_id"]:
        raise HTTPException(
            status_code=403, detail="Transaction does not belong to this vendor"
        )

    if tx["status"] != TransactionStatus.PENDING:
        raise HTTPException(status_code=400, detail="Transaction is not pending")

    now = datetime.now(timezone.utc)

    updates = {
        "status": TransactionStatus.REJECTED,
        "rejection_reason": reason,
        "processed_by": user["user_id"],
        "processed_by_name": user["name"],
        "processed_at": now.isoformat(),
    }

    await db.transactions.update_one(
        {"transaction_id": transaction_id}, {"$set": updates}
    )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


# Vendor complete withdrawal with screenshot upload
@api_router.post("/vendor/transactions/{transaction_id}/upload-proof")
async def vendor_upload_proof(
    transaction_id: str,
    proof_image: UploadFile = File(...),
    user: dict = Depends(require_vendor),
):
    """Vendor uploads proof of payment for withdrawal transactions"""
    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.get("vendor_id") != vendor["vendor_id"]:
        raise HTTPException(
            status_code=403, detail="Transaction does not belong to this vendor"
        )

    content = await proof_image.read()
    proof_image_data = base64.b64encode(content).decode("utf-8")

    now = datetime.now(timezone.utc)
    await db.transactions.update_one(
        {"transaction_id": transaction_id},
        {
            "$set": {
                "vendor_proof_image": proof_image_data,
                "vendor_proof_uploaded_at": now.isoformat(),
                "vendor_proof_uploaded_by": user["user_id"],
                "vendor_proof_uploaded_by_name": user["name"],
            }
        },
    )

    return {"message": "Proof uploaded successfully", "transaction_id": transaction_id}


# Vendor complete withdrawal with screenshot upload
@api_router.post("/vendor/transactions/{transaction_id}/complete")
async def vendor_complete_withdrawal(
    transaction_id: str,
    proof_image: UploadFile = File(...),
    user: dict = Depends(require_vendor),
):
    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.get("vendor_id") != vendor["vendor_id"]:
        raise HTTPException(
            status_code=403, detail="Transaction does not belong to this vendor"
        )

    if tx.get("transaction_type") != TransactionType.WITHDRAWAL:
        raise HTTPException(
            status_code=400, detail="Only withdrawals can be completed with proof"
        )

    if tx["status"] not in [TransactionStatus.PENDING, TransactionStatus.APPROVED]:
        raise HTTPException(
            status_code=400, detail="Transaction cannot be completed in current status"
        )

    now = datetime.now(timezone.utc)

    # Handle proof image upload
    content = await proof_image.read()
    proof_image_data = base64.b64encode(content).decode("utf-8")

    updates = {
        "status": TransactionStatus.COMPLETED,
        "vendor_proof_image": proof_image_data,
        "processed_by": user["user_id"],
        "processed_by_name": user["name"],
        "processed_at": now.isoformat(),
    }

    await db.transactions.update_one(
        {"transaction_id": transaction_id}, {"$set": updates}
    )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


# Vendor settlements
@api_router.get("/vendors/{vendor_id}/settlements")
async def get_vendor_settlements(
    vendor_id: str, user: dict = Depends(get_current_user)
):
    settlements = (
        await db.vendor_settlements.find({"vendor_id": vendor_id}, {"_id": 0})
        .sort("created_at", -1)
        .to_list(1000)
    )
    return settlements


@api_router.get("/settlements/{settlement_id}/statement")
async def get_settlement_statement(
    settlement_id: str, user: dict = Depends(get_current_user)
):
    """Get full settlement statement with underlying transactions."""
    settlement = await db.vendor_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )
    if not settlement:
        raise HTTPException(status_code=404, detail="Settlement not found")
    tx_ids = settlement.get("transaction_ids", [])
    transactions = []
    if tx_ids:
        transactions = await db.transactions.find(
            {"transaction_id": {"$in": tx_ids}},
            {
                "_id": 0,
                "transaction_id": 1,
                "transaction_type": 1,
                "amount": 1,
                "currency": 1,
                "base_amount": 1,
                "base_currency": 1,
                "client_name": 1,
                "reference": 1,
                "created_at": 1,
                "status": 1,
            },
        ).to_list(1000)
    vendor = await db.vendors.find_one(
        {"vendor_id": settlement.get("vendor_id")},
        {"_id": 0, "vendor_name": 1, "contact_person": 1, "email": 1, "phone": 1},
    )
    return {
        "settlement": settlement,
        "transactions": transactions,
        "vendor": vendor or {},
    }


# Admin settle vendor balance
class VendorSettlementRequest(BaseModel):
    settlement_type: str  # "bank" or "cash"
    destination_account_id: str  # Required - treasury account
    commission_amount: float = 0  # Manual commission entry
    charges_amount: float = 0  # Additional charges/fees
    charges_description: Optional[str] = None
    # Multi-currency support
    source_currency: str = "USD"  # Currency of transactions
    destination_currency: str = "USD"  # Currency of destination treasury
    exchange_rate: float = 1.0  # Conversion rate
    settlement_amount_in_dest_currency: Optional[float] = (
        None  # Final amount in destination currency
    )


@api_router.post("/vendors/{vendor_id}/settle")
async def settle_vendor_balance(
    vendor_id: str,
    settlement_request: VendorSettlementRequest,
    user: dict = Depends(require_accountant_or_admin),
):
    vendor = await db.vendors.find_one({"vendor_id": vendor_id}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    # Get approved transactions for this vendor that haven't been settled
    pending_txs = await db.transactions.find(
        {
            "vendor_id": vendor_id,
            "destination_type": "vendor",
            "status": {
                "$in": [TransactionStatus.APPROVED, TransactionStatus.COMPLETED]
            },
            "settled": {"$ne": True},
        },
        {"_id": 0},
    ).to_list(1000)

    # Also get approved IE entries for this vendor that haven't been settled
    pending_ie = await db.income_expenses.find(
        {
            "vendor_id": vendor_id,
            "status": "completed",
            "settled": {"$ne": True},
            "converted_to_loan": {"$ne": True},
        },
        {"_id": 0},
    ).to_list(1000)

    if not pending_txs and not pending_ie:
        raise HTTPException(status_code=400, detail="No pending transactions to settle")

    # Calculate NET amounts - deposits minus withdrawals, using base_amount for source currency
    source_currency = settlement_request.source_currency
    gross_amount = 0
    for tx in pending_txs:
        # Determine the amount to use based on currency match
        if tx.get("base_currency") == source_currency and tx.get("base_amount"):
            # Use base amount in the source currency
            tx_amount = tx["base_amount"]
        elif tx.get("currency") == source_currency:
            # Use main amount if it matches source currency
            tx_amount = tx["amount"]
        else:
            # Default to main amount
            tx_amount = tx["amount"]

        # Add for deposits, subtract for withdrawals (NET calculation)
        if tx.get("transaction_type") == "deposit":
            gross_amount += tx_amount
        elif tx.get("transaction_type") == "withdrawal":
            gross_amount -= tx_amount
        else:
            # Default: add
            gross_amount += tx_amount

    # Add IE entries to gross amount
    # Income entries = vendor receives (like deposit), Expense entries = vendor pays (like withdrawal)
    ie_entry_ids = []
    for ie in pending_ie:
        if ie.get("currency") == source_currency:
            ie_amount = ie["amount"]
        else:
            ie_amount = ie.get("amount_usd", ie["amount"])

        if ie["entry_type"] == "income":
            gross_amount += ie_amount
        else:  # expense
            gross_amount -= ie_amount
        ie_entry_ids.append(ie["entry_id"])

    # Manual commission and charges
    commission_amount = settlement_request.commission_amount
    charges_amount = settlement_request.charges_amount

    # Net amount before currency conversion
    net_amount_source = gross_amount - commission_amount - charges_amount

    # Calculate settlement amount in destination currency
    if settlement_request.settlement_amount_in_dest_currency is not None:
        # Admin entered final amount directly
        settlement_amount = settlement_request.settlement_amount_in_dest_currency
    else:
        # Use exchange rate
        settlement_amount = round(
            net_amount_source * settlement_request.exchange_rate, 2
        )

    settlement_id = f"vstl_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    dest_account_id = settlement_request.destination_account_id
    dest = await db.treasury_accounts.find_one(
        {"account_id": dest_account_id}, {"_id": 0}
    )
    if not dest:
        raise HTTPException(
            status_code=404, detail="Settlement destination account not found"
        )

    settlement_doc = {
        "settlement_id": settlement_id,
        "vendor_id": vendor_id,
        "vendor_name": vendor["vendor_name"],
        "settlement_type": settlement_request.settlement_type,
        "gross_amount": gross_amount,
        "source_currency": settlement_request.source_currency,
        "commission_amount": commission_amount,
        "charges_amount": charges_amount,
        "charges_description": settlement_request.charges_description,
        "net_amount_source": net_amount_source,
        "exchange_rate": settlement_request.exchange_rate,
        "destination_currency": settlement_request.destination_currency,
        "settlement_amount": settlement_amount,
        "transaction_count": len(pending_txs) + len(pending_ie),
        "transaction_ids": [tx["transaction_id"] for tx in pending_txs],
        "ie_entry_ids": ie_entry_ids,
        "settlement_destination_id": dest_account_id,
        "settlement_destination_name": dest["account_name"],
        "status": VendorSettlementStatus.PENDING,  # Settlements go to pending first
        "created_at": now.isoformat(),
        "settled_at": None,  # Will be set on approval
        "approved_at": None,
        "approved_by": None,
        "approved_by_name": None,
        "rejection_reason": None,
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.vendor_settlements.insert_one(settlement_doc)

    # Mark transactions as pending settlement (not fully settled yet)
    await db.transactions.update_many(
        {"transaction_id": {"$in": [tx["transaction_id"] for tx in pending_txs]}},
        {
            "$set": {
                "settlement_id": settlement_id,
                "settlement_status": "pending_approval",
            }
        },
    )

    # Mark IE entries as pending settlement
    if ie_entry_ids:
        await db.income_expenses.update_many(
            {"entry_id": {"$in": ie_entry_ids}},
            {
                "$set": {
                    "settlement_id": settlement_id,
                    "settlement_status": "pending_approval",
                }
            },
        )

    return await db.vendor_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )


# Get all pending settlements (for approval page)
@api_router.get("/settlements/pending")
async def get_pending_settlements(user: dict = Depends(require_accountant_or_admin)):
    """Get all pending vendor settlements awaiting approval"""
    settlements = (
        await db.vendor_settlements.find(
            {"status": VendorSettlementStatus.PENDING}, {"_id": 0}
        )
        .sort("created_at", -1)
        .to_list(1000)
    )
    return settlements


# Approve vendor settlement
@api_router.post("/settlements/{settlement_id}/approve")
async def approve_settlement(
    settlement_id: str, user: dict = Depends(require_accountant_or_admin)
):
    """Approve a pending vendor settlement"""
    settlement = await db.vendor_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )
    if not settlement:
        raise HTTPException(status_code=404, detail="Settlement not found")

    if settlement["status"] != VendorSettlementStatus.PENDING:
        raise HTTPException(status_code=400, detail="Settlement is not pending")

    now = datetime.now(timezone.utc)

    # Update settlement status
    await db.vendor_settlements.update_one(
        {"settlement_id": settlement_id},
        {
            "$set": {
                "status": VendorSettlementStatus.APPROVED,
                "approved_at": now.isoformat(),
                "approved_by": user["user_id"],
                "approved_by_name": user["name"],
                "settled_at": now.isoformat(),
            }
        },
    )

    # Mark transactions as fully settled
    await db.transactions.update_many(
        {"settlement_id": settlement_id},
        {"$set": {"settled": True, "settlement_status": "completed"}},
    )

    # Mark IE entries as fully settled
    ie_entry_ids = settlement.get("ie_entry_ids", [])
    if ie_entry_ids:
        await db.income_expenses.update_many(
            {"entry_id": {"$in": ie_entry_ids}},
            {"$set": {"settled": True, "settlement_status": "completed"}},
        )

    # Update treasury balance with settlement amount
    await db.treasury_accounts.update_one(
        {"account_id": settlement["settlement_destination_id"]},
        {
            "$inc": {"balance": settlement["settlement_amount"]},
            "$set": {"updated_at": now.isoformat()},
        },
    )

    # Update vendor stats
    await db.vendors.update_one(
        {"vendor_id": settlement["vendor_id"]},
        {
            "$inc": {
                "total_volume": settlement["gross_amount"],
                "total_commission": settlement["commission_amount"],
            }
        },
    )

    # Record treasury transaction for history
    treasury_tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
    treasury_tx_doc = {
        "treasury_transaction_id": treasury_tx_id,
        "account_id": settlement["settlement_destination_id"],
        "transaction_type": "settlement_in",
        "amount": settlement["settlement_amount"],
        "currency": settlement["destination_currency"],
        "reference": f"Vendor Settlement: {settlement['vendor_name']}",
        "settlement_id": settlement_id,
        "vendor_id": settlement["vendor_id"],
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.treasury_transactions.insert_one(treasury_tx_doc)

    return await db.vendor_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )


# Reject vendor settlement
@api_router.post("/settlements/{settlement_id}/reject")
async def reject_settlement(
    settlement_id: str,
    reason: str = "",
    user: dict = Depends(require_accountant_or_admin),
):
    """Reject a pending vendor settlement"""
    settlement = await db.vendor_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )
    if not settlement:
        raise HTTPException(status_code=404, detail="Settlement not found")

    if settlement["status"] != VendorSettlementStatus.PENDING:
        raise HTTPException(status_code=400, detail="Settlement is not pending")

    now = datetime.now(timezone.utc)

    # Update settlement status
    await db.vendor_settlements.update_one(
        {"settlement_id": settlement_id},
        {
            "$set": {
                "status": VendorSettlementStatus.REJECTED,
                "rejection_reason": reason,
                "approved_at": now.isoformat(),
                "approved_by": user["user_id"],
                "approved_by_name": user["name"],
            }
        },
    )

    # Reset transaction settlement status so they can be settled again
    await db.transactions.update_many(
        {"settlement_id": settlement_id},
        {"$set": {"settlement_id": None, "settlement_status": None}},
    )

    return await db.vendor_settlements.find_one(
        {"settlement_id": settlement_id}, {"_id": 0}
    )


# ============== TRANSACTIONS ROUTES ==============


@api_router.get("/transactions")
async def get_transactions(
    user: dict = Depends(get_current_user),
    client_id: Optional[str] = None,
    transaction_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
):
    query = {}
    if client_id:
        query["client_id"] = client_id
    if transaction_type:
        query["transaction_type"] = transaction_type
    if status:
        query["status"] = status

    transactions = (
        await db.transactions.find(query, {"_id": 0})
        .sort("created_at", -1)
        .to_list(limit)
    )

    # Enrich transactions with client email
    client_ids = list(
        set(tx.get("client_id") for tx in transactions if tx.get("client_id"))
    )
    clients_map = {}
    if client_ids:
        clients = await db.clients.find(
            {"client_id": {"$in": client_ids}}, {"_id": 0, "client_id": 1, "email": 1}
        ).to_list(len(client_ids))
        clients_map = {c["client_id"]: c.get("email", "") for c in clients}

    for tx in transactions:
        tx["client_email"] = clients_map.get(tx.get("client_id"), "")

    return transactions


@api_router.get("/transactions/pending")
async def get_pending_transactions(user: dict = Depends(require_accountant_or_admin)):
    """Get all pending transactions for accountant approval"""
    transactions = (
        await db.transactions.find({"status": TransactionStatus.PENDING}, {"_id": 0})
        .sort("created_at", -1)
        .to_list(1000)
    )
    return transactions


@api_router.get("/transactions/{transaction_id}")
async def get_transaction(transaction_id: str, user: dict = Depends(get_current_user)):
    transaction = await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return transaction


@api_router.post("/transactions")
async def create_transaction(
    client_id: str = Form(...),
    transaction_type: str = Form(...),
    amount: float = Form(...),
    currency: str = Form("USD"),
    base_currency: str = Form("USD"),
    base_amount: Optional[float] = Form(None),
    destination_type: str = Form("treasury"),
    destination_account_id: Optional[str] = Form(None),
    psp_id: Optional[str] = Form(None),
    vendor_id: Optional[str] = Form(None),
    commission_paid_by: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    reference: Optional[str] = Form(None),
    # Client bank details (for withdrawal to bank)
    client_bank_name: Optional[str] = Form(None),
    client_bank_account_name: Optional[str] = Form(None),
    client_bank_account_number: Optional[str] = Form(None),
    client_bank_swift_iban: Optional[str] = Form(None),
    client_bank_currency: Optional[str] = Form(None),
    save_bank_to_client: Optional[str] = Form(
        None
    ),  # 'true' to save bank to client profile
    # Client USDT details (for withdrawal to USDT)
    client_usdt_address: Optional[str] = Form(None),
    client_usdt_network: Optional[str] = Form(None),
    transaction_mode: Optional[str] = Form("bank"),
    collecting_person_name: Optional[str] = Form(None),
    collecting_person_number: Optional[str] = Form(None),
    proof_image: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)

    # ===== DUPLICATE DETECTION =====
    # Check 1: If reference is provided, ensure it's unique
    if reference:
        existing_by_ref = await db.transactions.find_one(
            {"reference": reference}, {"_id": 0}
        )
        if existing_by_ref:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate transaction: Reference '{reference}' already exists (Transaction ID: {existing_by_ref['transaction_id']})",
            )

    # Check 2: Same client, type, amount within 5 minutes (prevents accidental double-submit)
    five_minutes_ago = (now - timedelta(minutes=5)).isoformat()
    duplicate_query = {
        "client_id": client_id,
        "transaction_type": transaction_type,
        "amount": amount,
        "created_at": {"$gte": five_minutes_ago},
    }
    # Add destination filters for more precise matching
    if destination_type == "psp" and psp_id:
        duplicate_query["psp_id"] = psp_id
    elif destination_type == "vendor" and vendor_id:
        duplicate_query["vendor_id"] = vendor_id
    elif destination_type == "treasury" and destination_account_id:
        duplicate_query["destination_account_id"] = destination_account_id

    recent_duplicate = await db.transactions.find_one(duplicate_query, {"_id": 0})
    if recent_duplicate:
        raise HTTPException(
            status_code=400,
            detail=f"Possible duplicate: Similar transaction created {recent_duplicate.get('created_at', 'recently')} (Transaction ID: {recent_duplicate['transaction_id']}). Wait 5 minutes or use a unique reference.",
        )
    # ===== END DUPLICATE DETECTION =====

    # Verify client exists
    client = await db.clients.find_one({"client_id": client_id}, {"_id": 0})
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    # Verify destination based on type
    destination_account = None
    psp_info = None
    vendor_info = None

    if destination_type == "treasury" and destination_account_id:
        destination_account = await db.treasury_accounts.find_one(
            {"account_id": destination_account_id}, {"_id": 0}
        )
        if not destination_account:
            raise HTTPException(status_code=404, detail="Destination account not found")
    elif destination_type == "usdt" and destination_account_id:
        # For USDT deposits, select the USDT treasury account
        destination_account = await db.treasury_accounts.find_one(
            {"account_id": destination_account_id}, {"_id": 0}
        )
        if not destination_account:
            raise HTTPException(
                status_code=404, detail="USDT treasury account not found"
            )
    elif destination_type == "psp" and psp_id:
        psp_info = await db.psps.find_one({"psp_id": psp_id}, {"_id": 0})
        if not psp_info:
            raise HTTPException(status_code=404, detail="PSP not found")
    elif destination_type == "vendor" and vendor_id:
        vendor_info = await db.vendors.find_one({"vendor_id": vendor_id}, {"_id": 0})
        if not vendor_info:
            raise HTTPException(status_code=404, detail="Vendor not found")

    # Save bank account to client profile if requested
    if (
        destination_type in ["bank", "vendor"]
        and save_bank_to_client == "true"
        and client_bank_name
        and client_bank_account_number
    ):
        existing_bank = await db.client_bank_accounts.find_one(
            {
                "client_id": client_id,
                "account_number": client_bank_account_number,
                "bank_name": client_bank_name,
            }
        )
        if not existing_bank:
            bank_account_id = f"cba_{uuid.uuid4().hex[:12]}"
            bank_doc = {
                "bank_account_id": bank_account_id,
                "client_id": client_id,
                "bank_name": client_bank_name,
                "account_name": client_bank_account_name,
                "account_number": client_bank_account_number,
                "swift_iban": client_bank_swift_iban,
                "currency": client_bank_currency or "USD",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "created_by": user["user_id"],
            }
            await db.client_bank_accounts.insert_one(bank_doc)

    tx_id = f"tx_{uuid.uuid4().hex[:12]}"
    # now is already defined at the top for duplicate detection

    # Handle proof image upload
    proof_image_data = None
    if proof_image:
        content = await proof_image.read()
        proof_image_data = base64.b64encode(content).decode("utf-8")

    # Calculate USD amount if base currency is different
    usd_amount = amount
    if base_currency and base_currency != "USD" and base_amount:
        usd_amount = convert_to_usd(base_amount, base_currency)

    # Calculate PSP commission if applicable
    commission_amount = 0.0
    net_amount = usd_amount
    expected_settlement_date = None

    if destination_type == "psp" and psp_info:
        commission_rate = psp_info.get("commission_rate", 0) / 100
        commission_amount = round(usd_amount * commission_rate, 2)

        # If commission paid by client, net amount is reduced
        if commission_paid_by == CommissionPaidBy.CLIENT:
            net_amount = usd_amount - commission_amount
        # If commission paid by broker, net amount stays same (broker absorbs)

        # Calculate expected settlement date
        settlement_days = psp_info.get("settlement_days", 1)
        expected_settlement_date = (now + timedelta(days=settlement_days)).isoformat()

        # Calculate reserve fund amount per-transaction
        reserve_fund_rate_pct = psp_info.get(
            "reserve_fund_rate", psp_info.get("chargeback_rate", 0)
        )
        psp_reserve_fund_amount = round(usd_amount * reserve_fund_rate_pct / 100, 2)

        # Calculate holding release date (when funds will be released from PSP holding)
        holding_days = psp_info.get("holding_days", 0)
        holding_release_date = (
            (now + timedelta(days=holding_days)).isoformat()
            if holding_days > 0
            else None
        )

    # ===== BROKER COMMISSION CALCULATION =====
    broker_commission_rate = 0.0
    broker_commission_amount = 0.0
    broker_commission_base = 0.0
    commission_settings = await db.app_settings.find_one(
        {"setting_type": "commission"}, {"_id": 0}
    )
    if commission_settings and commission_settings.get("commission_enabled"):
        if transaction_type == TransactionType.DEPOSIT:
            broker_commission_rate = commission_settings.get(
                "deposit_commission_rate", 0
            )
        elif transaction_type == TransactionType.WITHDRAWAL:
            broker_commission_rate = commission_settings.get(
                "withdrawal_commission_rate", 0
            )
        if broker_commission_rate > 0:
            broker_commission_amount = round(
                usd_amount * broker_commission_rate / 100, 2
            )
            b_base = (
                base_amount
                if (base_currency and base_currency != "USD" and base_amount)
                else usd_amount
            )
            broker_commission_base = round(b_base * broker_commission_rate / 100, 2)

    # Calculate vendor commission at creation time
    vendor_commission_rate = 0.0
    vendor_commission_amount = 0.0
    vendor_commission_base_amount = 0.0
    if destination_type == "vendor" and vendor_info:
        tx_mode = transaction_mode or "bank"
        if transaction_type == TransactionType.DEPOSIT:
            if tx_mode == "cash":
                vendor_commission_rate = vendor_info.get(
                    "deposit_commission_cash", vendor_info.get("deposit_commission", 0)
                )
            else:
                vendor_commission_rate = vendor_info.get("deposit_commission", 0)
        elif transaction_type == TransactionType.WITHDRAWAL:
            if tx_mode == "cash":
                vendor_commission_rate = vendor_info.get(
                    "withdrawal_commission_cash",
                    vendor_info.get("withdrawal_commission", 0),
                )
            else:
                vendor_commission_rate = vendor_info.get("withdrawal_commission", 0)
        if vendor_commission_rate > 0:
            vendor_commission_amount = round(
                usd_amount * vendor_commission_rate / 100, 2
            )
            v_base = (
                base_amount
                if (base_currency and base_currency != "USD" and base_amount)
                else usd_amount
            )
            vendor_commission_base_amount = round(
                v_base * vendor_commission_rate / 100, 2
            )

    tx_doc = {
        "transaction_id": tx_id,
        "client_id": client_id,
        "client_name": f"{client['first_name']} {client['last_name']}",
        "transaction_type": transaction_type,
        "amount": usd_amount,
        "currency": "USD",
        "base_currency": base_currency or "USD",
        "base_amount": base_amount if base_currency != "USD" else None,
        "destination_type": destination_type,
        "destination_account_id": (
            destination_account_id if destination_type in ["treasury", "usdt"] else None
        ),
        "destination_account_name": (
            destination_account["account_name"] if destination_account else None
        ),
        "destination_bank_name": (
            destination_account["bank_name"] if destination_account else None
        ),
        # Client bank details (for withdrawal to bank or vendor)
        "client_bank_name": (
            client_bank_name if destination_type in ["bank", "vendor"] else None
        ),
        "client_bank_account_name": (
            client_bank_account_name if destination_type in ["bank", "vendor"] else None
        ),
        "client_bank_account_number": (
            client_bank_account_number
            if destination_type in ["bank", "vendor"]
            else None
        ),
        "client_bank_swift_iban": (
            client_bank_swift_iban if destination_type in ["bank", "vendor"] else None
        ),
        "client_bank_currency": (
            client_bank_currency if destination_type in ["bank", "vendor"] else None
        ),
        # Client USDT details (for withdrawal to USDT)
        "client_usdt_address": (
            client_usdt_address if destination_type == "usdt" else None
        ),
        "client_usdt_network": (
            client_usdt_network if destination_type == "usdt" else None
        ),
        "psp_id": psp_id if destination_type == "psp" else None,
        "psp_name": psp_info["psp_name"] if psp_info else None,
        "psp_commission_rate": psp_info["commission_rate"] if psp_info else None,
        "psp_commission_amount": commission_amount if psp_info else None,
        "psp_commission_paid_by": commission_paid_by if psp_info else None,
        "psp_net_amount": net_amount if psp_info else None,
        "psp_expected_settlement_date": expected_settlement_date,
        "psp_holding_days": psp_info.get("holding_days", 0) if psp_info else None,
        "psp_holding_release_date": holding_release_date if psp_info else None,
        "psp_reserve_fund_rate": (
            psp_info.get("reserve_fund_rate", psp_info.get("chargeback_rate", 0))
            if psp_info
            else None
        ),
        "psp_chargeback_rate": (
            psp_info.get("reserve_fund_rate", psp_info.get("chargeback_rate", 0))
            if psp_info
            else None
        ),
        "psp_reserve_fund_amount": psp_reserve_fund_amount if psp_info else None,
        "psp_chargeback_amount": psp_reserve_fund_amount if psp_info else None,
        "vendor_id": vendor_id if destination_type == "vendor" else None,
        "vendor_name": vendor_info["vendor_name"] if vendor_info else None,
        "vendor_deposit_commission": (
            vendor_info["deposit_commission"]
            if vendor_info and transaction_type == TransactionType.DEPOSIT
            else None
        ),
        "vendor_withdrawal_commission": (
            vendor_info["withdrawal_commission"]
            if vendor_info and transaction_type == TransactionType.WITHDRAWAL
            else None
        ),
        "vendor_commission_rate": (
            vendor_commission_rate if vendor_commission_rate > 0 else None
        ),
        "vendor_commission_amount": (
            vendor_commission_amount if vendor_commission_amount > 0 else None
        ),
        "vendor_commission_base_amount": (
            vendor_commission_base_amount if vendor_commission_base_amount > 0 else None
        ),
        "vendor_commission_base_currency": (
            base_currency if vendor_commission_base_amount > 0 else None
        ),
        "vendor_proof_image": None,
        "accountant_proof_image": None,
        "transaction_mode": transaction_mode or "bank",
        "collecting_person_name": (
            collecting_person_name if transaction_mode == "cash" else None
        ),
        "collecting_person_number": (
            collecting_person_number if transaction_mode == "cash" else None
        ),
        "status": TransactionStatus.PENDING,
        "description": description,
        "reference": reference or f"REF{uuid.uuid4().hex[:8].upper()}",
        "proof_image": proof_image_data,
        "created_by": user["user_id"],
        "created_by_name": user["name"],
        "processed_by": None,
        "processed_by_name": None,
        "rejection_reason": None,
        "settled": False,
        "settlement_id": None,
        "settlement_status": None,
        "broker_commission_rate": broker_commission_rate,
        "broker_commission_amount": broker_commission_amount,
        "broker_commission_base_amount": broker_commission_base,
        "broker_commission_base_currency": base_currency or "USD",
        "created_at": now.isoformat(),
        "processed_at": None,
    }

    await db.transactions.insert_one(tx_doc)

    # Update PSP pending balance if this is a PSP transaction
    if destination_type == "psp" and psp_info:
        await db.psps.update_one(
            {"psp_id": psp_id}, {"$inc": {"pending_settlement": net_amount}}
        )

    # Update vendor pending balance if this is a vendor transaction
    if destination_type == "vendor" and vendor_info:
        await db.vendors.update_one(
            {"vendor_id": vendor_id}, {"$inc": {"pending_settlement": usd_amount}}
        )

    result = await db.transactions.find_one({"transaction_id": tx_id}, {"_id": 0})
    return result


@api_router.put("/transactions/{transaction_id}")
async def update_transaction(
    transaction_id: str,
    update_data: TransactionUpdate,
    user: dict = Depends(get_current_user),
):
    updates = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    now = datetime.now(timezone.utc)

    # If approving/completing or rejecting transaction
    if updates.get("status") in [
        TransactionStatus.APPROVED,
        TransactionStatus.COMPLETED,
        TransactionStatus.REJECTED,
    ]:
        updates["processed_by"] = user["user_id"]
        updates["processed_by_name"] = user["name"]
        updates["processed_at"] = now.isoformat()

        # Update treasury balance if completed
        if updates.get("status") == TransactionStatus.COMPLETED and tx.get(
            "destination_account_id"
        ):
            balance_change = (
                tx["amount"]
                if tx["transaction_type"] == TransactionType.DEPOSIT
                else -tx["amount"]
            )
            await db.treasury_accounts.update_one(
                {"account_id": tx["destination_account_id"]},
                {
                    "$inc": {"balance": balance_change},
                    "$set": {"updated_at": now.isoformat()},
                },
            )

    await db.transactions.update_one(
        {"transaction_id": transaction_id}, {"$set": updates}
    )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


@api_router.post("/transactions/{transaction_id}/approve")
async def approve_transaction(
    transaction_id: str,
    source_account_id: Optional[str] = None,
    require_proof: bool = True,
    user: dict = Depends(require_accountant_or_admin),
):
    """Approve a pending transaction"""
    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx["status"] != TransactionStatus.PENDING:
        raise HTTPException(status_code=400, detail="Transaction is not pending")

    now = datetime.now(timezone.utc)

    updates = {
        "status": TransactionStatus.APPROVED,
        "processed_by": user["user_id"],
        "processed_by_name": user["name"],
        "processed_at": now.isoformat(),
    }

    # For deposits, require proof of payment screenshot
    if tx["transaction_type"] == TransactionType.DEPOSIT:
        if require_proof and not tx.get("accountant_proof_image"):
            raise HTTPException(
                status_code=400,
                detail="Proof of payment screenshot is required for deposit approvals",
            )

    # For withdrawals with bank/usdt destination, require source account
    if tx["transaction_type"] == TransactionType.WITHDRAWAL:
        if tx.get("destination_type") in ["bank", "usdt"]:
            if not source_account_id:
                raise HTTPException(
                    status_code=400,
                    detail="Source account is required for withdrawal approvals",
                )

            # Verify source account exists and has sufficient balance
            source_account = await db.treasury_accounts.find_one(
                {"account_id": source_account_id}, {"_id": 0}
            )
            if not source_account:
                raise HTTPException(status_code=404, detail="Source account not found")

            # Calculate withdrawal amount in source account's currency
            source_currency = source_account.get("currency", "USD")
            tx_currency = tx.get("currency", "USD")
            withdrawal_amount = tx["amount"]

            # Convert if currencies are different
            if tx_currency == "USD" and source_currency != "USD":
                # Convert from USD to source account currency
                withdrawal_amount = convert_from_usd(tx["amount"], source_currency)
            elif tx_currency != "USD" and source_currency == "USD":
                # Convert from transaction currency to USD
                withdrawal_amount = convert_to_usd(tx["amount"], tx_currency)
            elif tx_currency != source_currency:
                # Convert via USD as intermediate
                usd_amount = convert_to_usd(tx["amount"], tx_currency)
                withdrawal_amount = convert_from_usd(usd_amount, source_currency)

            if source_account.get("balance", 0) < withdrawal_amount:
                raise HTTPException(
                    status_code=400,
                    detail=f"Insufficient balance in source account. Required: {withdrawal_amount:,.2f} {source_currency}, Available: {source_account.get('balance', 0):,.2f} {source_currency}",
                )

            # Deduct from source account
            await db.treasury_accounts.update_one(
                {"account_id": source_account_id},
                {
                    "$inc": {"balance": -withdrawal_amount},
                    "$set": {"updated_at": now.isoformat()},
                },
            )

            updates["source_account_id"] = source_account_id
            updates["source_account_name"] = source_account.get("account_name")
            updates["withdrawal_amount_in_source_currency"] = withdrawal_amount
            updates["source_currency"] = source_currency

            # Record treasury transaction
            treasury_tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
            treasury_tx_doc = {
                "treasury_transaction_id": treasury_tx_id,
                "account_id": source_account_id,
                "transaction_type": "withdrawal",
                "amount": -withdrawal_amount,
                "currency": source_currency,
                "original_amount": tx["amount"],
                "original_currency": tx_currency,
                "exchange_rate": (
                    withdrawal_amount / tx["amount"] if tx["amount"] > 0 else 1
                ),
                "reference": f"Withdrawal: {tx.get('client_name', 'Client')} - {tx.get('reference', '')}",
                "transaction_id": transaction_id,
                "client_id": tx.get("client_id"),
                "created_at": now.isoformat(),
                "created_by": user["user_id"],
                "created_by_name": user["name"],
            }
            await db.treasury_transactions.insert_one(treasury_tx_doc)

    # Update treasury balance for deposits going to treasury
    if (
        tx.get("destination_account_id")
        and tx["transaction_type"] == TransactionType.DEPOSIT
    ):
        # Get the destination account to check its currency
        dest_account = await db.treasury_accounts.find_one(
            {"account_id": tx["destination_account_id"]}, {"_id": 0}
        )

        if dest_account:
            dest_currency = dest_account.get("currency", "USD")
            tx_currency = tx.get("currency", "USD")
            deposit_amount = tx["amount"]

            # Convert if currencies are different
            if tx_currency == "USD" and dest_currency != "USD":
                # Convert from USD to destination currency
                deposit_amount = convert_from_usd(tx["amount"], dest_currency)
            elif tx_currency != "USD" and dest_currency == "USD":
                # Convert from source currency to USD
                deposit_amount = convert_to_usd(tx["amount"], tx_currency)
            elif tx_currency != dest_currency:
                # Convert via USD as intermediate
                usd_amount = convert_to_usd(tx["amount"], tx_currency)
                deposit_amount = convert_from_usd(usd_amount, dest_currency)

            await db.treasury_accounts.update_one(
                {"account_id": tx["destination_account_id"]},
                {
                    "$inc": {"balance": deposit_amount},
                    "$set": {"updated_at": now.isoformat()},
                },
            )

            # Record treasury transaction for deposit
            treasury_tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
            treasury_tx_doc = {
                "treasury_transaction_id": treasury_tx_id,
                "account_id": tx["destination_account_id"],
                "transaction_type": "deposit",
                "amount": deposit_amount,
                "currency": dest_currency,
                "original_amount": tx["amount"],
                "original_currency": tx_currency,
                "exchange_rate": (
                    deposit_amount / tx["amount"] if tx["amount"] > 0 else 1
                ),
                "reference": f"Deposit: {tx.get('client_name', 'Client')} - {tx.get('reference', '')}",
                "transaction_id": transaction_id,
                "client_id": tx.get("client_id"),
                "created_at": now.isoformat(),
                "created_by": user["user_id"],
                "created_by_name": user["name"],
            }
            await db.treasury_transactions.insert_one(treasury_tx_doc)

    await db.transactions.update_one(
        {"transaction_id": transaction_id}, {"$set": updates}
    )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


@api_router.post("/transactions/{transaction_id}/upload-proof")
async def upload_transaction_proof(
    transaction_id: str,
    proof_image: UploadFile = File(...),
    user: dict = Depends(require_accountant_or_admin),
):
    """Upload proof of payment for deposit and withdrawal transactions"""
    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    # Allow uploading proof for pending deposits and withdrawals
    if tx["transaction_type"] not in [
        TransactionType.WITHDRAWAL,
        TransactionType.DEPOSIT,
    ]:
        raise HTTPException(
            status_code=400,
            detail="Proof upload is only for deposit and withdrawal transactions",
        )

    content = await proof_image.read()
    proof_image_data = base64.b64encode(content).decode("utf-8")

    now = datetime.now(timezone.utc)
    await db.transactions.update_one(
        {"transaction_id": transaction_id},
        {
            "$set": {
                "accountant_proof_image": proof_image_data,
                "proof_uploaded_at": now.isoformat(),
                "proof_uploaded_by": user["user_id"],
                "proof_uploaded_by_name": user["name"],
            }
        },
    )

    return {"message": "Proof uploaded successfully", "transaction_id": transaction_id}


@api_router.post("/transactions/{transaction_id}/reject")
async def reject_transaction(
    transaction_id: str,
    reason: str = "",
    user: dict = Depends(require_accountant_or_admin),
):
    """Reject a pending transaction"""
    tx = await db.transactions.find_one({"transaction_id": transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx["status"] != TransactionStatus.PENDING:
        raise HTTPException(status_code=400, detail="Transaction is not pending")

    now = datetime.now(timezone.utc)

    updates = {
        "status": TransactionStatus.REJECTED,
        "rejection_reason": reason,
        "processed_by": user["user_id"],
        "processed_by_name": user["name"],
        "processed_at": now.isoformat(),
    }

    await db.transactions.update_one(
        {"transaction_id": transaction_id}, {"$set": updates}
    )

    return await db.transactions.find_one(
        {"transaction_id": transaction_id}, {"_id": 0}
    )


# ============== REPORTS/ANALYTICS ROUTES ==============


@api_router.get("/reports/dashboard")
async def get_dashboard_stats(user: dict = Depends(get_current_user)):
    # Get client stats
    total_clients = await db.clients.count_documents({})
    approved_clients = await db.clients.count_documents(
        {"kyc_status": ClientStatus.APPROVED}
    )
    pending_clients = await db.clients.count_documents(
        {"kyc_status": ClientStatus.PENDING}
    )

    # Get treasury stats
    total_treasury = await db.treasury_accounts.count_documents({})
    active_treasury = await db.treasury_accounts.count_documents(
        {"status": TreasuryAccountStatus.ACTIVE}
    )

    # Get total treasury balance in USD (converting all currencies)
    all_accounts = await db.treasury_accounts.find(
        {"status": TreasuryAccountStatus.ACTIVE}, {"_id": 0}
    ).to_list(1000)
    total_balance_usd = sum(
        convert_to_usd(acc.get("balance", 0), acc.get("currency", "USD"))
        for acc in all_accounts
    )

    # Get transaction stats
    total_transactions = await db.transactions.count_documents({})
    pending_transactions = await db.transactions.count_documents(
        {"status": TransactionStatus.PENDING}
    )

    # Get deposits/withdrawals totals
    deposit_pipeline = [
        {
            "$match": {
                "transaction_type": TransactionType.DEPOSIT,
                "status": {
                    "$in": [TransactionStatus.APPROVED, TransactionStatus.COMPLETED]
                },
            }
        },
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
    ]
    withdrawal_pipeline = [
        {
            "$match": {
                "transaction_type": TransactionType.WITHDRAWAL,
                "status": {
                    "$in": [TransactionStatus.APPROVED, TransactionStatus.COMPLETED]
                },
            }
        },
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
    ]

    deposit_result = await db.transactions.aggregate(deposit_pipeline).to_list(1)
    withdrawal_result = await db.transactions.aggregate(withdrawal_pipeline).to_list(1)

    total_deposits = deposit_result[0]["total"] if deposit_result else 0
    total_withdrawals = withdrawal_result[0]["total"] if withdrawal_result else 0

    return {
        "clients": {
            "total": total_clients,
            "approved": approved_clients,
            "pending": pending_clients,
        },
        "treasury": {
            "total": total_treasury,
            "active": active_treasury,
            "total_balance": total_balance_usd,
        },
        "transactions": {
            "total": total_transactions,
            "pending": pending_transactions,
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
        },
    }


@api_router.get("/reports/transactions-summary")
async def get_transactions_summary(
    user: dict = Depends(get_current_user), days: int = 30
):
    from_date = datetime.now(timezone.utc) - timedelta(days=days)

    pipeline = [
        {
            "$addFields": {
                "created_date": {"$dateFromString": {"dateString": "$created_at"}}
            }
        },
        {"$match": {"created_date": {"$gte": from_date}}},
        {
            "$group": {
                "_id": {
                    "date": {
                        "$dateToString": {"format": "%Y-%m-%d", "date": "$created_date"}
                    },
                    "type": "$transaction_type",
                },
                "count": {"$sum": 1},
                "total_amount": {"$sum": "$amount"},
            }
        },
        {"$sort": {"_id.date": 1}},
    ]

    results = await db.transactions.aggregate(pipeline).to_list(1000)

    summary = {}
    for r in results:
        date = r["_id"]["date"]
        tx_type = r["_id"]["type"]
        if date not in summary:
            summary[date] = {"date": date, "deposits": 0, "withdrawals": 0}
        if tx_type == TransactionType.DEPOSIT:
            summary[date]["deposits"] = r["total_amount"]
        elif tx_type == TransactionType.WITHDRAWAL:
            summary[date]["withdrawals"] = r["total_amount"]

    return list(summary.values())


@api_router.get("/reports/client-analytics")
async def get_client_analytics(user: dict = Depends(get_current_user)):
    # KYC status distribution
    kyc_pipeline = [{"$group": {"_id": "$kyc_status", "count": {"$sum": 1}}}]
    kyc_stats = await db.clients.aggregate(kyc_pipeline).to_list(10)

    # Country distribution
    country_pipeline = [
        {"$match": {"country": {"$ne": None}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    country_stats = await db.clients.aggregate(country_pipeline).to_list(10)

    return {
        "kyc_distribution": [
            {"status": s["_id"], "count": s["count"]} for s in kyc_stats
        ],
        "country_distribution": [
            {"country": c["_id"], "count": c["count"]} for c in country_stats
        ],
    }


@api_router.get("/reports/recent-activity")
async def get_recent_activity(user: dict = Depends(get_current_user), limit: int = 10):
    transactions = (
        await db.transactions.find({}, {"_id": 0}).sort("created_at", -1).to_list(limit)
    )
    clients = (
        await db.clients.find({}, {"_id": 0}).sort("created_at", -1).to_list(limit)
    )

    return {"recent_transactions": transactions, "recent_clients": clients}


# ============== SEED DATA ROUTE ==============


@api_router.post("/seed")
async def seed_demo_data():
    """Seed demo data for testing"""
    now = datetime.now(timezone.utc)

    # Create admin user if not exists
    admin = await db.users.find_one({"email": "admin@fxbroker.com"}, {"_id": 0})
    if not admin:
        admin_doc = {
            "user_id": f"user_{uuid.uuid4().hex[:12]}",
            "email": "admin@fxbroker.com",
            "password_hash": hash_password("admin123"),
            "name": "System Admin",
            "role": UserRole.ADMIN,
            "picture": None,
            "is_active": True,
            "created_at": now.isoformat(),
        }
        await db.users.insert_one(admin_doc)

    # Create accountant user if not exists
    accountant = await db.users.find_one(
        {"email": "accountant@fxbroker.com"}, {"_id": 0}
    )
    if not accountant:
        accountant_doc = {
            "user_id": f"user_{uuid.uuid4().hex[:12]}",
            "email": "accountant@fxbroker.com",
            "password_hash": hash_password("accountant123"),
            "name": "Finance Manager",
            "role": UserRole.ACCOUNTANT,
            "picture": None,
            "is_active": True,
            "created_at": now.isoformat(),
        }
        await db.users.insert_one(accountant_doc)

    # Create treasury accounts
    treasury_accounts_data = [
        {
            "account_name": "Main Operating Account",
            "account_type": "bank",
            "bank_name": "Chase Bank",
            "account_number": "****1234",
            "currency": "USD",
        },
        {
            "account_name": "Client Funds Account",
            "account_type": "bank",
            "bank_name": "Bank of America",
            "account_number": "****5678",
            "currency": "USD",
        },
        {
            "account_name": "EUR Account",
            "account_type": "bank",
            "bank_name": "Deutsche Bank",
            "account_number": "****9012",
            "currency": "EUR",
        },
        {
            "account_name": "AED Account",
            "account_type": "bank",
            "bank_name": "Emirates NBD",
            "account_number": "****3456",
            "currency": "AED",
        },
    ]

    treasury_ids = []
    for ta in treasury_accounts_data:
        existing = await db.treasury_accounts.find_one(
            {"account_name": ta["account_name"]}, {"_id": 0}
        )
        if not existing:
            account_id = f"treasury_{uuid.uuid4().hex[:12]}"
            ta_doc = {
                "account_id": account_id,
                **ta,
                "balance": 50000.0,
                "status": TreasuryAccountStatus.ACTIVE,
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
            }
            await db.treasury_accounts.insert_one(ta_doc)
            treasury_ids.append(account_id)
        else:
            treasury_ids.append(existing["account_id"])

    # Create sample clients
    sample_clients = [
        {
            "first_name": "John",
            "last_name": "Smith",
            "email": "john.smith@email.com",
            "phone": "+1234567890",
            "country": "USA",
            "kyc_status": ClientStatus.APPROVED,
        },
        {
            "first_name": "Emma",
            "last_name": "Wilson",
            "email": "emma.wilson@email.com",
            "phone": "+4477889900",
            "country": "UK",
            "kyc_status": ClientStatus.APPROVED,
        },
        {
            "first_name": "Michael",
            "last_name": "Brown",
            "email": "michael.brown@email.com",
            "phone": "+6199887766",
            "country": "Australia",
            "kyc_status": ClientStatus.PENDING,
        },
        {
            "first_name": "Sarah",
            "last_name": "Davis",
            "email": "sarah.davis@email.com",
            "phone": "+4912345678",
            "country": "Germany",
            "kyc_status": ClientStatus.APPROVED,
        },
        {
            "first_name": "James",
            "last_name": "Miller",
            "email": "james.miller@email.com",
            "phone": "+8187654321",
            "country": "Japan",
            "kyc_status": ClientStatus.PENDING,
        },
    ]

    client_ids = []
    for c in sample_clients:
        existing = await db.clients.find_one({"email": c["email"]}, {"_id": 0})
        if not existing:
            client_id = f"client_{uuid.uuid4().hex[:12]}"
            client_doc = {
                "client_id": client_id,
                **c,
                "kyc_documents": [],
                "notes": None,
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
            }
            await db.clients.insert_one(client_doc)
            client_ids.append(client_id)
        else:
            client_ids.append(existing["client_id"])

    # Create sample transactions
    for i, client_id in enumerate(client_ids[:3]):
        client = await db.clients.find_one({"client_id": client_id}, {"_id": 0})
        if client:
            tx_id = f"tx_{uuid.uuid4().hex[:12]}"
            tx_doc = {
                "transaction_id": tx_id,
                "client_id": client_id,
                "client_name": f"{client['first_name']} {client['last_name']}",
                "transaction_type": TransactionType.DEPOSIT,
                "amount": [5000, 10000, 3000][i],
                "currency": "USD",
                "base_currency": "USD",
                "base_amount": None,
                "destination_type": "treasury",
                "destination_account_id": treasury_ids[0] if treasury_ids else None,
                "destination_account_name": "Main Operating Account",
                "destination_bank_name": "Chase Bank",
                "psp_id": None,
                "psp_name": None,
                "psp_commission_rate": None,
                "status": TransactionStatus.PENDING,
                "description": "Initial deposit",
                "reference": f"DEP{uuid.uuid4().hex[:8].upper()}",
                "proof_image": None,
                "created_by": None,
                "created_by_name": "System",
                "processed_by": None,
                "processed_by_name": None,
                "rejection_reason": None,
                "settled": False,
                "settlement_id": None,
                "settlement_status": None,
                "created_at": (now - timedelta(days=i + 1)).isoformat(),
                "processed_at": None,
            }
            await db.transactions.insert_one(tx_doc)

    # Create sample PSPs
    psp_data = [
        {
            "psp_name": "Stripe",
            "commission_rate": 2.9,
            "settlement_days": 2,
            "description": "Credit card payments",
        },
        {
            "psp_name": "PayPal",
            "commission_rate": 3.5,
            "settlement_days": 3,
            "description": "PayPal payments",
        },
        {
            "psp_name": "Skrill",
            "commission_rate": 2.5,
            "settlement_days": 1,
            "description": "E-wallet payments",
        },
    ]

    for psp in psp_data:
        existing = await db.psps.find_one({"psp_name": psp["psp_name"]}, {"_id": 0})
        if not existing and treasury_ids:
            psp_id = f"psp_{uuid.uuid4().hex[:12]}"
            psp_doc = {
                "psp_id": psp_id,
                "psp_name": psp["psp_name"],
                "commission_rate": psp["commission_rate"],
                "settlement_days": psp["settlement_days"],
                "settlement_destination_id": treasury_ids[0],  # Main Operating Account
                "min_settlement_amount": 100,
                "description": psp["description"],
                "total_volume": 0.0,
                "total_commission": 0.0,
                "pending_settlement": 0.0,
                "status": PSPStatus.ACTIVE,
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
            }
            await db.psps.insert_one(psp_doc)

    # Create sample vendors
    vendor_data = [
        {
            "vendor_name": "MoneyExchange Pro",
            "email": "vendor1@fxbroker.com",
            "password": "vendor123",
            "deposit_commission": 1.5,
            "withdrawal_commission": 2.0,
            "bank_settlement_commission": 0.5,
            "cash_settlement_commission": 1.0,
            "description": "Premium exchange vendor",
        },
        {
            "vendor_name": "FastPay Solutions",
            "email": "vendor2@fxbroker.com",
            "password": "vendor123",
            "deposit_commission": 2.0,
            "withdrawal_commission": 2.5,
            "bank_settlement_commission": 0.3,
            "cash_settlement_commission": 0.8,
            "description": "Fast payment processing",
        },
    ]

    for v in vendor_data:
        existing = await db.vendors.find_one(
            {"vendor_name": v["vendor_name"]}, {"_id": 0}
        )
        if not existing and treasury_ids:
            vendor_id = f"vendor_{uuid.uuid4().hex[:12]}"
            user_id = f"user_{uuid.uuid4().hex[:12]}"

            # Create user account for vendor
            user_doc = {
                "user_id": user_id,
                "email": v["email"],
                "password_hash": hash_password(v["password"]),
                "name": v["vendor_name"],
                "role": UserRole.VENDOR,
                "vendor_id": vendor_id,
                "picture": None,
                "is_active": True,
                "created_at": now.isoformat(),
            }
            await db.users.insert_one(user_doc)

            vendor_doc = {
                "vendor_id": vendor_id,
                "user_id": user_id,
                "vendor_name": v["vendor_name"],
                "email": v["email"],
                "deposit_commission": v["deposit_commission"],
                "withdrawal_commission": v["withdrawal_commission"],
                "bank_settlement_commission": v["bank_settlement_commission"],
                "cash_settlement_commission": v["cash_settlement_commission"],
                "settlement_destination_id": treasury_ids[0],
                "description": v["description"],
                "total_volume": 0.0,
                "total_commission": 0.0,
                "pending_settlement": 0.0,
                "status": VendorStatus.ACTIVE,
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
            }
            await db.vendors.insert_one(vendor_doc)

    return {"message": "Demo data seeded successfully"}


# ============== INCOME & EXPENSES ROUTES ==============


@api_router.get("/income-expenses")
async def get_income_expenses(
    entry_type: Optional[str] = None,
    category: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    treasury_account_id: Optional[str] = None,
    vendor_id: Optional[str] = None,
    limit: int = 100,
    user: dict = Depends(get_current_user),
):
    """Get all income and expense entries with optional filters"""
    query = {}

    if entry_type:
        query["entry_type"] = entry_type
    if category:
        query["category"] = category
    if treasury_account_id:
        query["treasury_account_id"] = treasury_account_id
    if vendor_id:
        query["vendor_id"] = vendor_id
    if start_date:
        query["date"] = {"$gte": start_date}
    if end_date:
        if "date" in query:
            query["date"]["$lte"] = end_date
        else:
            query["date"] = {"$lte": end_date}

    entries = (
        await db.income_expenses.find(query, {"_id": 0})
        .sort("date", -1)
        .limit(limit)
        .to_list(limit)
    )

    # Batch fetch treasury accounts to avoid N+1 queries
    treasury_ids = list(
        set(
            e.get("treasury_account_id")
            for e in entries
            if e.get("treasury_account_id")
        )
    )
    treasury_map = {}
    if treasury_ids:
        treasuries = await db.treasury_accounts.find(
            {"account_id": {"$in": treasury_ids}}, {"_id": 0}
        ).to_list(len(treasury_ids))
        treasury_map = {t["account_id"]: t["account_name"] for t in treasuries}

    for entry in entries:
        if entry.get("treasury_account_id"):
            entry["treasury_account_name"] = treasury_map.get(
                entry["treasury_account_id"], "Unknown"
            )

    return entries


@api_router.get("/income-expenses/reports/summary")
async def get_income_expense_summary(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    """Get income vs expense summary report"""
    query = {}
    if start_date:
        query["date"] = {"$gte": start_date}
    if end_date:
        if "date" in query:
            query["date"]["$lte"] = end_date
        else:
            query["date"] = {"$lte": end_date}

    # Get all entries (exclude converted to loan to avoid double-counting)
    entries = await db.income_expenses.find(
        {**query, "converted_to_loan": {"$ne": True}}, {"_id": 0}
    ).to_list(10000)

    # Use .get() with fallback to handle entries without amount_usd
    total_income = sum(
        e.get(
            "amount_usd", convert_to_usd(e.get("amount", 0), e.get("currency", "USD"))
        )
        for e in entries
        if e["entry_type"] == IncomeExpenseType.INCOME
    )
    total_expense = sum(
        e.get(
            "amount_usd", convert_to_usd(e.get("amount", 0), e.get("currency", "USD"))
        )
        for e in entries
        if e["entry_type"] == IncomeExpenseType.EXPENSE
    )
    net_profit = total_income - total_expense

    # Category breakdown
    income_by_category = {}
    expense_by_category = {}

    for entry in entries:
        cat = entry.get("custom_category") or entry.get("category", "other")
        amount = entry.get(
            "amount_usd",
            convert_to_usd(entry.get("amount", 0), entry.get("currency", "USD")),
        )
        if entry["entry_type"] == IncomeExpenseType.INCOME:
            income_by_category[cat] = income_by_category.get(cat, 0) + amount
        else:
            expense_by_category[cat] = expense_by_category.get(cat, 0) + amount

    return {
        "total_income_usd": round(total_income, 2),
        "total_expense_usd": round(total_expense, 2),
        "net_profit_usd": round(net_profit, 2),
        "income_by_category": {k: round(v, 2) for k, v in income_by_category.items()},
        "expense_by_category": {k: round(v, 2) for k, v in expense_by_category.items()},
        "entry_count": len(entries),
    }


@api_router.get("/income-expenses/reports/monthly")
async def get_monthly_report(
    year: Optional[int] = None, user: dict = Depends(get_current_user)
):
    """Get monthly P&L report"""
    if not year:
        year = datetime.now().year

    # Get entries for the year
    start_date = f"{year}-01-01"
    end_date = f"{year}-12-31"

    entries = await db.income_expenses.find(
        {"date": {"$gte": start_date, "$lte": end_date}}, {"_id": 0}
    ).to_list(10000)

    # Group by month
    monthly_data = {}
    for month in range(1, 13):
        month_str = f"{year}-{month:02d}"
        monthly_data[month_str] = {"income": 0, "expense": 0}

    for entry in entries:
        month_str = entry.get("date", "")[:7]  # YYYY-MM
        if month_str in monthly_data:
            amt_usd = entry.get("amount_usd") or convert_to_usd(
                entry.get("amount", 0), entry.get("currency", "USD")
            )
            if entry["entry_type"] == IncomeExpenseType.INCOME:
                monthly_data[month_str]["income"] += amt_usd
            else:
                monthly_data[month_str]["expense"] += amt_usd

    # Calculate net for each month
    result = []
    for month, data in monthly_data.items():
        result.append(
            {
                "month": month,
                "income": round(data["income"], 2),
                "expense": round(data["expense"], 2),
                "net": round(data["income"] - data["expense"], 2),
            }
        )

    return result


@api_router.get("/income-expenses/categories")
async def get_categories(user: dict = Depends(get_current_user)):
    """Get available categories and custom categories"""
    income_categories = [
        {"value": "commission", "label": "Commission Income"},
        {"value": "service_fee", "label": "Service Fees"},
        {"value": "interest", "label": "Interest Income"},
        {"value": "other", "label": "Other Income"},
    ]

    expense_categories = [
        {"value": "bank_fee", "label": "Bank Fees"},
        {"value": "transfer_charge", "label": "Transfer Charges"},
        {"value": "vendor_payment", "label": "Vendor Payments"},
        {"value": "operational", "label": "Operational Costs"},
        {"value": "marketing", "label": "Marketing"},
        {"value": "software", "label": "Software/Subscriptions"},
        {"value": "other", "label": "Other Expenses"},
    ]

    # Get custom categories from existing entries
    custom_income = await db.income_expenses.distinct(
        "custom_category", {"entry_type": "income", "custom_category": {"$ne": None}}
    )
    custom_expense = await db.income_expenses.distinct(
        "custom_category", {"entry_type": "expense", "custom_category": {"$ne": None}}
    )

    return {
        "income_categories": income_categories,
        "expense_categories": expense_categories,
        "custom_income_categories": custom_income,
        "custom_expense_categories": custom_expense,
    }


@api_router.get("/income-expenses/export-template")
async def get_ie_import_template_route(user: dict = Depends(get_current_user)):
    """Download Excel template for bulk importing income/expense entries"""
    import openpyxl
    from io import BytesIO
    from fastapi.responses import StreamingResponse

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Income_Expenses"

    # Headers
    headers = [
        "Entry Type",
        "Category",
        "Amount",
        "Currency",
        "Date",
        "Description",
        "Reference",
    ]
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = openpyxl.styles.Font(bold=True)

    # Example rows
    examples = [
        [
            "income",
            "commission",
            1000,
            "USD",
            "2025-01-15",
            "Monthly commission",
            "INV-001",
        ],
        [
            "expense",
            "bank_fee",
            50,
            "USD",
            "2025-01-15",
            "Wire transfer fee",
            "REF-002",
        ],
        [
            "income",
            "service_fee",
            500,
            "EUR",
            "2025-01-16",
            "Service charge",
            "INV-003",
        ],
        [
            "expense",
            "operational",
            200,
            "USD",
            "2025-01-17",
            "Office supplies",
            "REF-004",
        ],
    ]
    for row_idx, row_data in enumerate(examples, 2):
        for col_idx, value in enumerate(row_data, 1):
            ws.cell(row=row_idx, column=col_idx, value=value)

    # Adjust column widths
    for col in ws.columns:
        max_length = max(len(str(cell.value or "")) for cell in col)
        ws.column_dimensions[col[0].column_letter].width = min(max_length + 2, 30)

    # Save to BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": "attachment; filename=income_expenses_template.xlsx"
        },
    )


@api_router.post("/income-expenses/bulk-import")
async def bulk_import_ie_entries_route(
    user: dict = Depends(require_accountant_or_admin),
    file: UploadFile = File(...),
    treasury_account_id: str = Form(...),
):
    """
    Bulk import income/expense entries from Excel file.
    Excel columns expected: entry_type, category, amount, currency, date, description, reference
    """
    import openpyxl
    from io import BytesIO

    # Verify treasury account
    treasury = await db.treasury_accounts.find_one(
        {"account_id": treasury_account_id}, {"_id": 0}
    )
    if not treasury:
        raise HTTPException(status_code=404, detail="Treasury account not found")

    # Read Excel file
    contents = await file.read()
    try:
        wb = openpyxl.load_workbook(BytesIO(contents))
        ws = wb.active
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Excel file: {str(e)}")

    # Get headers from first row
    headers = [str(cell.value).lower().strip() if cell.value else "" for cell in ws[1]]

    # Map expected columns
    col_map = {}
    expected = [
        "entry_type",
        "type",
        "category",
        "amount",
        "currency",
        "date",
        "description",
        "reference",
    ]
    for idx, h in enumerate(headers):
        for exp in expected:
            if exp in h:
                col_map[exp] = idx
                break

    if "amount" not in col_map:
        raise HTTPException(
            status_code=400, detail="Excel file must have an 'amount' column"
        )

    now = datetime.now(timezone.utc)
    imported = 0
    errors = []

    for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
        try:
            # Get values
            amount_val = row[col_map.get("amount", 0)]
            if not amount_val or float(amount_val) <= 0:
                continue

            amount = float(amount_val)
            entry_type_val = (
                row[col_map.get("entry_type", col_map.get("type", 0))]
                if "entry_type" in col_map or "type" in col_map
                else "expense"
            )
            entry_type = (
                "income"
                if str(entry_type_val).lower().strip()
                in ["income", "in", "credit", "cr"]
                else "expense"
            )
            category = (
                str(row[col_map.get("category", 0)] or "other")
                .lower()
                .replace(" ", "_")
            )
            currency = str(row[col_map.get("currency", 0)] or "USD").upper()
            date_val = row[col_map.get("date", 0)]
            description = str(row[col_map.get("description", 0)] or "")
            reference = str(row[col_map.get("reference", 0)] or "")

            # Parse date
            if date_val:
                if isinstance(date_val, datetime):
                    entry_date = date_val.strftime("%Y-%m-%d")
                else:
                    entry_date = str(date_val)[:10]
            else:
                entry_date = now.strftime("%Y-%m-%d")

            entry_id = f"ie_{uuid.uuid4().hex[:12]}"
            amount_usd = convert_to_usd(amount, currency)

            entry_doc = {
                "entry_id": entry_id,
                "entry_type": entry_type,
                "category": category,
                "custom_category": None,
                "amount": amount,
                "currency": currency,
                "amount_usd": amount_usd,
                "treasury_account_id": treasury_account_id,
                "treasury_account_name": treasury["account_name"],
                "vendor_id": None,
                "vendor_name": None,
                "vendor_supplier_id": None,
                "vendor_supplier_name": None,
                "client_id": None,
                "client_name": None,
                "ie_category_id": None,
                "ie_category_name": None,
                "description": description if description != "None" else "",
                "reference": reference if reference != "None" else "",
                "date": entry_date,
                "status": "completed",
                "converted_to_loan": False,
                "loan_id": None,
                "vendor_proof_image": None,
                "invoice_file": None,
                "created_at": now.isoformat(),
                "created_by": user["user_id"],
                "created_by_name": user["name"],
                "imported_from": file.filename,
            }

            await db.income_expenses.insert_one(entry_doc)

            # Update treasury balance
            if entry_type == "income":
                await db.treasury_accounts.update_one(
                    {"account_id": treasury_account_id},
                    {
                        "$inc": {"balance": amount},
                        "$set": {"updated_at": now.isoformat()},
                    },
                )
            else:
                await db.treasury_accounts.update_one(
                    {"account_id": treasury_account_id},
                    {
                        "$inc": {"balance": -amount},
                        "$set": {"updated_at": now.isoformat()},
                    },
                )

            imported += 1
        except Exception as e:
            errors.append(f"Row {row_idx}: {str(e)}")

    return {
        "message": f"Import completed",
        "imported": imported,
        "errors": errors[:10] if errors else [],
    }


@api_router.get("/income-expenses/{entry_id}")
async def get_income_expense(entry_id: str, user: dict = Depends(get_current_user)):
    """Get a single income/expense entry"""
    entry = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return entry


@api_router.post("/income-expenses")
async def create_income_expense(
    entry_data: IncomeExpenseCreate, user: dict = Depends(get_current_user)
):
    """Create a new income or expense entry, optionally linked to a vendor/supplier/client for approval"""
    if entry_data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    if not entry_data.category and not entry_data.ie_category_id:
        raise HTTPException(
            status_code=400, detail="Either a category or custom category is required"
        )

    if not entry_data.vendor_id and not entry_data.treasury_account_id:
        raise HTTPException(
            status_code=400,
            detail="Either an exchanger or treasury account is required",
        )

    # Exchanger-linked entry: auto-create pending approval in vendor portal
    vendor_info = None
    if entry_data.vendor_id:
        vendor_info = await db.vendors.find_one(
            {"vendor_id": entry_data.vendor_id}, {"_id": 0}
        )
        if not vendor_info:
            raise HTTPException(status_code=404, detail="Exchanger not found")

    # Vendor Supplier (service supplier like rent, utilities) - lookup for name
    vendor_supplier_info = None
    if entry_data.vendor_supplier_id:
        vendor_supplier_info = await db.vendor_suppliers.find_one(
            {"supplier_id": entry_data.vendor_supplier_id}, {"_id": 0}
        )
        if not vendor_supplier_info:
            raise HTTPException(status_code=404, detail="Vendor supplier not found")

    # Client - lookup for name
    client_info = None
    if entry_data.client_id:
        client_info = await db.clients.find_one(
            {"client_id": entry_data.client_id}, {"_id": 0}
        )
        if not client_info:
            raise HTTPException(status_code=404, detail="Client not found")

    # IE Category - lookup for name
    ie_category_info = None
    if entry_data.ie_category_id:
        ie_category_info = await db.ie_categories.find_one(
            {"category_id": entry_data.ie_category_id}, {"_id": 0}
        )
        if not ie_category_info:
            raise HTTPException(status_code=404, detail="Category not found")

    treasury = None
    if entry_data.treasury_account_id and not entry_data.vendor_id:
        treasury = await db.treasury_accounts.find_one(
            {"account_id": entry_data.treasury_account_id}, {"_id": 0}
        )
        if not treasury:
            raise HTTPException(status_code=404, detail="Treasury account not found")

    entry_id = f"ie_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    entry_date = entry_data.date if entry_data.date else now.isoformat()[:10]

    # Calculate USD equivalent
    amount_usd = convert_to_usd(entry_data.amount, entry_data.currency)

    # Determine initial status: pending if exchanger-linked, completed otherwise
    status = "pending_vendor" if vendor_info else "completed"

    # Calculate vendor commission at creation time
    ie_commission_rate = 0.0
    ie_commission_amount = 0.0
    ie_commission_base_amount = 0.0
    if vendor_info:
        tx_mode = entry_data.transaction_mode or "bank"
        if entry_data.entry_type == "income":
            if tx_mode == "cash":
                ie_commission_rate = vendor_info.get(
                    "deposit_commission_cash", vendor_info.get("deposit_commission", 0)
                )
            else:
                ie_commission_rate = vendor_info.get("deposit_commission", 0)
        else:
            if tx_mode == "cash":
                ie_commission_rate = vendor_info.get(
                    "withdrawal_commission_cash",
                    vendor_info.get("withdrawal_commission", 0),
                )
            else:
                ie_commission_rate = vendor_info.get("withdrawal_commission", 0)
        if ie_commission_rate > 0:
            ie_commission_amount = round(amount_usd * ie_commission_rate / 100, 2)
            ie_commission_base_amount = round(
                entry_data.amount * ie_commission_rate / 100, 2
            )

    entry_doc = {
        "entry_id": entry_id,
        "entry_type": entry_data.entry_type,
        "category": entry_data.category,
        "custom_category": entry_data.custom_category,
        "amount": entry_data.amount,
        "currency": entry_data.currency,
        "amount_usd": amount_usd,
        "treasury_account_id": entry_data.treasury_account_id,
        "treasury_account_name": treasury["account_name"] if treasury else None,
        "vendor_id": entry_data.vendor_id,
        "vendor_name": vendor_info["vendor_name"] if vendor_info else None,
        "vendor_supplier_id": entry_data.vendor_supplier_id,
        "vendor_supplier_name": (
            vendor_supplier_info["name"] if vendor_supplier_info else None
        ),
        "client_id": entry_data.client_id,
        "client_name": (
            f"{client_info['first_name']} {client_info['last_name']}"
            if client_info
            else None
        ),
        "ie_category_id": entry_data.ie_category_id,
        "ie_category_name": ie_category_info["name"] if ie_category_info else None,
        "vendor_bank_account_name": entry_data.vendor_bank_account_name,
        "vendor_bank_account_number": entry_data.vendor_bank_account_number,
        "vendor_bank_ifsc": entry_data.vendor_bank_ifsc,
        "vendor_bank_branch": entry_data.vendor_bank_branch,
        "description": entry_data.description,
        "reference": entry_data.reference,
        "date": entry_date,
        "transaction_mode": entry_data.transaction_mode or "bank",
        "collecting_person_name": (
            entry_data.collecting_person_name
            if entry_data.transaction_mode == "cash"
            else None
        ),
        "collecting_person_number": (
            entry_data.collecting_person_number
            if entry_data.transaction_mode == "cash"
            else None
        ),
        "vendor_commission_rate": (
            ie_commission_rate if ie_commission_rate > 0 else None
        ),
        "vendor_commission_amount": (
            ie_commission_amount if ie_commission_amount > 0 else None
        ),
        "vendor_commission_base_amount": (
            ie_commission_base_amount if ie_commission_base_amount > 0 else None
        ),
        "vendor_commission_base_currency": (
            entry_data.currency if ie_commission_base_amount > 0 else None
        ),
        "status": status,
        "converted_to_loan": False,
        "loan_id": None,
        "vendor_proof_image": None,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.income_expenses.insert_one(entry_doc)

    # Only update treasury if not vendor-linked (vendor must approve first)
    if not vendor_info and treasury:
        # Convert amount to treasury currency if different
        treasury_currency = treasury.get("currency", "USD")
        entry_currency = entry_data.currency

        if treasury_currency.upper() != entry_currency.upper():
            converted_amount = convert_currency(
                entry_data.amount, entry_currency, treasury_currency
            )
        else:
            converted_amount = entry_data.amount

        if entry_data.entry_type == IncomeExpenseType.INCOME:
            await db.treasury_accounts.update_one(
                {"account_id": entry_data.treasury_account_id},
                {
                    "$inc": {"balance": converted_amount},
                    "$set": {"updated_at": now.isoformat()},
                },
            )
        else:
            if treasury.get("balance", 0) < converted_amount:
                raise HTTPException(
                    status_code=400, detail="Insufficient balance in treasury account"
                )
            await db.treasury_accounts.update_one(
                {"account_id": entry_data.treasury_account_id},
                {
                    "$inc": {"balance": -converted_amount},
                    "$set": {"updated_at": now.isoformat()},
                },
            )

        # Record in treasury transactions
        tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
        tx_type = (
            "income" if entry_data.entry_type == IncomeExpenseType.INCOME else "expense"
        )
        tx_amount = (
            converted_amount
            if entry_data.entry_type == IncomeExpenseType.INCOME
            else -converted_amount
        )

        # Build reference from category name (either standard category or custom ie_category)
        category_label = (
            entry_data.category.replace("_", " ").title()
            if entry_data.category
            else (ie_category_info["name"] if ie_category_info else "Other")
        )

        # Include conversion info in reference if currencies differ
        conversion_note = (
            f" (Converted from {entry_data.amount:,.2f} {entry_currency})"
            if treasury_currency.upper() != entry_currency.upper()
            else ""
        )

        tx_doc = {
            "treasury_transaction_id": tx_id,
            "account_id": entry_data.treasury_account_id,
            "transaction_type": tx_type,
            "amount": tx_amount,
            "currency": treasury_currency,
            "original_amount": entry_data.amount,
            "original_currency": entry_currency,
            "reference": f"{category_label}: {entry_data.description or 'N/A'}{conversion_note}",
            "income_expense_id": entry_id,
            "created_at": now.isoformat(),
            "created_by": user["user_id"],
            "created_by_name": user["name"],
        }
        await db.treasury_transactions.insert_one(tx_doc)

    entry_doc.pop("_id", None)
    if treasury:
        entry_doc["treasury_account_name"] = treasury["account_name"]
    return entry_doc


@api_router.put("/income-expenses/{entry_id}")
async def update_income_expense(
    entry_id: str,
    update_data: IncomeExpenseUpdate,
    user: dict = Depends(get_current_user),
):
    """Update an income/expense entry (only description, reference, category - not amount)"""
    entry = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not update_dict:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Don't allow amount changes (would need to reverse treasury changes)
    if "amount" in update_dict:
        del update_dict["amount"]

    update_dict["updated_at"] = datetime.now(timezone.utc).isoformat()

    await db.income_expenses.update_one({"entry_id": entry_id}, {"$set": update_dict})

    updated = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    return updated


@api_router.delete("/income-expenses/{entry_id}")
async def delete_income_expense(entry_id: str, user: dict = Depends(require_admin)):
    """Delete an income/expense entry and reverse treasury balance"""
    entry = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    now = datetime.now(timezone.utc)

    # Reverse the treasury balance change
    if entry["entry_type"] == IncomeExpenseType.INCOME:
        # Reverse income - deduct from treasury
        await db.treasury_accounts.update_one(
            {"account_id": entry["treasury_account_id"]},
            {
                "$inc": {"balance": -entry["amount"]},
                "$set": {"updated_at": now.isoformat()},
            },
        )
    else:
        # Reverse expense - credit to treasury
        await db.treasury_accounts.update_one(
            {"account_id": entry["treasury_account_id"]},
            {
                "$inc": {"balance": entry["amount"]},
                "$set": {"updated_at": now.isoformat()},
            },
        )

    # Delete the entry
    await db.income_expenses.delete_one({"entry_id": entry_id})

    # Delete related treasury transaction
    await db.treasury_transactions.delete_one({"income_expense_id": entry_id})

    return {"message": "Entry deleted successfully"}


class ConvertToLoanRequest(BaseModel):
    borrower_name: str
    interest_rate: float = 0
    due_date: str
    treasury_account_id: Optional[str] = (
        None  # Optional - will use expense's treasury if not provided
    )
    notes: Optional[str] = None


@api_router.get("/loans/borrowers")
async def get_loan_borrowers(user: dict = Depends(get_current_user)):
    """Get list of borrower companies (vendors) plus unique borrower names from existing loans"""
    # Get all vendor companies as potential borrowers
    vendors = await db.vendors.find(
        {"status": "active"}, {"_id": 0, "vendor_id": 1, "vendor_name": 1, "email": 1}
    ).to_list(length=1000)

    # Also get unique borrower names from existing loans (for historical entries)
    loan_borrowers = await db.loans.distinct("borrower_name")

    # Combine into borrowers list
    borrowers = []
    seen_names = set()

    # Add vendors as borrower companies
    for v in vendors:
        name = v.get("vendor_name") or v.get("name")
        if name and name not in seen_names:
            borrowers.append(
                {
                    "name": name,
                    "vendor_id": v.get("vendor_id"),
                    "email": v.get("email"),
                    "type": "company",
                }
            )
            seen_names.add(name)

    # Add historical borrower names from loans (if not already in vendor list)
    for b in loan_borrowers:
        if b and b not in seen_names:
            borrowers.append(
                {"name": b, "vendor_id": None, "email": None, "type": "historical"}
            )
            seen_names.add(b)

    return {"borrowers": sorted(borrowers, key=lambda x: x["name"])}


@api_router.post("/income-expenses/{entry_id}/convert-to-loan")
async def convert_expense_to_loan(
    entry_id: str, req: ConvertToLoanRequest, user: dict = Depends(get_current_user)
):
    """Convert an expense entry to a loan (marks expense as converted, creates loan)"""
    entry = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    if entry["entry_type"] != "expense":
        raise HTTPException(
            status_code=400, detail="Only expenses can be converted to loans"
        )
    if entry.get("converted_to_loan"):
        raise HTTPException(
            status_code=400, detail="This expense has already been converted to a loan"
        )

    now = datetime.now(timezone.utc)
    loan_id = f"loan_{uuid.uuid4().hex[:12]}"

    # Use expense's treasury account if not provided (since money was already taken from vendor)
    treasury_account_id = req.treasury_account_id or entry.get("treasury_account_id")

    # Get treasury info for the loan record
    treasury = None
    treasury_name = "N/A"
    if treasury_account_id:
        treasury = await db.treasury_accounts.find_one(
            {"account_id": treasury_account_id}, {"_id": 0}
        )
        if treasury:
            treasury_name = treasury["account_name"]

    # If expense was already completed and had treasury impact, reverse it
    # (since converting to loan means the expense tracking should be via loan instead)
    if entry.get("treasury_account_id") and entry.get("status") == "completed":
        await db.treasury_accounts.update_one(
            {"account_id": entry["treasury_account_id"]},
            {
                "$inc": {"balance": entry["amount"]},
                "$set": {"updated_at": now.isoformat()},
            },
        )
        # Delete old treasury transaction
        await db.treasury_transactions.delete_one({"income_expense_id": entry_id})

    loan_doc = {
        "loan_id": loan_id,
        "borrower_name": req.borrower_name,
        "amount": entry["amount"],
        "currency": entry.get("currency", "USD"),
        "interest_rate": req.interest_rate,
        "loan_date": entry.get("date", now.isoformat()[:10]),
        "due_date": req.due_date,
        "repayment_mode": "lump_sum",
        "treasury_account_id": treasury_account_id,
        "source_treasury_name": treasury_name,
        "outstanding_balance": entry["amount"],
        "total_repaid": 0,
        "total_interest": 0,
        "status": "active",
        "repayment_count": 0,
        "converted_from_expense": entry_id,
        "notes": req.notes or f"Converted from expense: {entry.get('description', '')}",
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    # Only create treasury disbursement transaction if we have a valid treasury
    if treasury_account_id and treasury:
        # Deduct from treasury for loan disbursement
        await db.treasury_accounts.update_one(
            {"account_id": treasury_account_id},
            {
                "$inc": {"balance": -entry["amount"]},
                "$set": {"updated_at": now.isoformat()},
            },
        )

        # Create treasury transaction for loan
        await db.treasury_transactions.insert_one(
            {
                "treasury_transaction_id": f"ttx_{uuid.uuid4().hex[:12]}",
                "account_id": treasury_account_id,
                "account_name": treasury_name,
                "transaction_type": "loan_disbursement",
                "amount": -entry["amount"],
                "currency": entry.get("currency", "USD"),
                "reference": f"Loan to {req.borrower_name} (converted from expense {entry_id})",
                "loan_id": loan_id,
                "created_at": now.isoformat(),
                "created_by": user["user_id"],
                "created_by_name": user["name"],
            }
        )

    await db.loans.insert_one(loan_doc)

    # Mark expense as converted
    await db.income_expenses.update_one(
        {"entry_id": entry_id},
        {
            "$set": {
                "converted_to_loan": True,
                "loan_id": loan_id,
                "status": "converted_to_loan",
                "updated_at": now.isoformat(),
            }
        },
    )

    loan_doc.pop("_id", None)
    return {"message": "Expense converted to loan", "loan": loan_doc}


@api_router.post("/income-expenses/{entry_id}/vendor-approve")
async def vendor_approve_ie(entry_id: str, user: dict = Depends(require_vendor)):
    """Vendor approves a pending income/expense entry with commission calculation"""
    entry = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    if entry.get("status") != "pending_vendor":
        raise HTTPException(
            status_code=400, detail="Entry is not pending vendor approval"
        )

    # Verify this vendor is the assigned vendor
    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor or vendor.get("vendor_id") != entry.get("vendor_id"):
        raise HTTPException(status_code=403, detail="Not authorized for this entry")

    # Require proof upload
    if not entry.get("vendor_proof_image"):
        raise HTTPException(
            status_code=400, detail="Please upload proof screenshot before approving"
        )

    now = datetime.now(timezone.utc)

    # Calculate commission (same as deposit/withdrawal)
    # For IE entries: income = deposit-like (vendor receives), expense = withdrawal-like (vendor pays)
    tx_mode = entry.get("transaction_mode", "bank")
    if entry["entry_type"] == "income":
        if tx_mode == "cash":
            commission_rate = (
                vendor.get(
                    "deposit_commission_cash", vendor.get("deposit_commission", 0)
                )
                / 100
            )
        else:
            commission_rate = vendor.get("deposit_commission", 0) / 100
    else:
        if tx_mode == "cash":
            commission_rate = (
                vendor.get(
                    "withdrawal_commission_cash", vendor.get("withdrawal_commission", 0)
                )
                / 100
            )
        else:
            commission_rate = vendor.get("withdrawal_commission", 0) / 100

    amount = entry.get("amount", 0)
    amount_usd = entry.get("amount_usd") or convert_to_usd(
        amount, entry.get("currency", "USD")
    )
    commission_amount_usd = round(amount_usd * commission_rate, 2)
    commission_amount_base = round(amount * commission_rate, 2)

    # Update entry status with commission details
    await db.income_expenses.update_one(
        {"entry_id": entry_id},
        {
            "$set": {
                "status": "completed",
                "vendor_approved_at": now.isoformat(),
                "vendor_approved_by": user["user_id"],
                "vendor_commission_rate": commission_rate * 100,
                "vendor_commission_amount": commission_amount_usd,
                "vendor_commission_base_amount": commission_amount_base,
                "vendor_commission_base_currency": entry.get("currency", "USD"),
                "amount_usd": amount_usd,
            }
        },
    )

    # Update vendor's total commission and volume
    await db.vendors.update_one(
        {"vendor_id": vendor["vendor_id"]},
        {
            "$inc": {
                "total_commission": commission_amount_usd,
                "total_volume": amount_usd,
            },
            "$set": {"updated_at": now.isoformat()},
        },
    )

    return {
        "message": "Entry approved",
        "status": "completed",
        "vendor_commission_rate": commission_rate * 100,
        "vendor_commission_amount": commission_amount_usd,
        "vendor_commission_base_amount": commission_amount_base,
    }


@api_router.post("/income-expenses/{entry_id}/vendor-reject")
async def vendor_reject_ie(
    entry_id: str, reason: str = "", user: dict = Depends(require_vendor)
):
    """Vendor rejects a pending income/expense entry"""
    entry = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    if entry.get("status") != "pending_vendor":
        raise HTTPException(
            status_code=400, detail="Entry is not pending vendor approval"
        )

    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor or vendor.get("vendor_id") != entry.get("vendor_id"):
        raise HTTPException(status_code=403, detail="Not authorized for this entry")

    now = datetime.now(timezone.utc)
    await db.income_expenses.update_one(
        {"entry_id": entry_id},
        {
            "$set": {
                "status": "rejected",
                "rejection_reason": reason,
                "vendor_rejected_at": now.isoformat(),
            }
        },
    )

    return {"message": "Entry rejected"}


@api_router.post("/income-expenses/{entry_id}/vendor-upload-proof")
async def vendor_upload_ie_proof(
    entry_id: str,
    user: dict = Depends(require_vendor),
    proof_image: UploadFile = File(...),
):
    """Vendor uploads proof screenshot for income/expense entry"""
    entry = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor or vendor.get("vendor_id") != entry.get("vendor_id"):
        raise HTTPException(status_code=403, detail="Not authorized for this entry")

    import base64

    contents = await proof_image.read()
    b64 = base64.b64encode(contents).decode("utf-8")

    await db.income_expenses.update_one(
        {"entry_id": entry_id},
        {
            "$set": {
                "vendor_proof_image": b64,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    )

    return {"message": "Proof uploaded"}


@api_router.post("/income-expenses/{entry_id}/upload-invoice")
async def upload_ie_invoice(
    entry_id: str,
    user: dict = Depends(get_current_user),
    invoice_file: UploadFile = File(...),
):
    """Upload invoice/document to an income/expense entry"""
    entry = await db.income_expenses.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    import base64

    contents = await invoice_file.read()
    b64 = base64.b64encode(contents).decode("utf-8")

    # Store with filename info
    file_info = {
        "data": b64,
        "filename": invoice_file.filename,
        "content_type": invoice_file.content_type,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": user["user_id"],
        "uploaded_by_name": user["name"],
    }

    await db.income_expenses.update_one(
        {"entry_id": entry_id},
        {
            "$set": {
                "invoice_file": file_info,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    )

    return {
        "message": "Invoice uploaded successfully",
        "filename": invoice_file.filename,
    }


@api_router.get("/vendor/income-expenses")
async def get_vendor_ie_entries(user: dict = Depends(require_vendor)):
    """Get income/expense entries linked to this vendor"""
    vendor = await db.vendors.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    entries = (
        await db.income_expenses.find({"vendor_id": vendor["vendor_id"]}, {"_id": 0})
        .sort("created_at", -1)
        .to_list(500)
    )
    return entries


# ============== VENDOR SUPPLIERS (Service Suppliers) ROUTES ==============


@api_router.get("/vendor-suppliers")
async def get_vendor_suppliers(
    status: Optional[str] = None,
    search: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    """Get all vendor suppliers (service providers like rent, utilities)"""
    query = {}
    if status:
        query["status"] = status
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"contact_person": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}},
        ]

    suppliers = (
        await db.vendor_suppliers.find(query, {"_id": 0}).sort("name", 1).to_list(1000)
    )
    return suppliers


@api_router.get("/vendor-suppliers/{supplier_id}")
async def get_vendor_supplier(supplier_id: str, user: dict = Depends(get_current_user)):
    """Get a specific vendor supplier"""
    supplier = await db.vendor_suppliers.find_one(
        {"supplier_id": supplier_id}, {"_id": 0}
    )
    if not supplier:
        raise HTTPException(status_code=404, detail="Vendor supplier not found")
    return supplier


@api_router.post("/vendor-suppliers")
async def create_vendor_supplier(
    data: VendorSupplierCreate, user: dict = Depends(get_current_user)
):
    """Create a new vendor supplier (for services like rent, utilities)"""
    # Check for duplicate name
    existing = await db.vendor_suppliers.find_one(
        {"name": {"$regex": f"^{data.name}$", "$options": "i"}}
    )
    if existing:
        raise HTTPException(
            status_code=400, detail="A supplier with this name already exists"
        )

    supplier_id = f"vs_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    supplier_doc = {
        "supplier_id": supplier_id,
        "name": data.name,
        "contact_person": data.contact_person,
        "email": data.email,
        "phone": data.phone,
        "address": data.address,
        "bank_name": data.bank_name,
        "bank_account_name": data.bank_account_name,
        "bank_account_number": data.bank_account_number,
        "bank_ifsc": data.bank_ifsc,
        "bank_branch": data.bank_branch,
        "notes": data.notes,
        "status": VendorSupplierStatus.ACTIVE,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "created_by": user["user_id"],
    }

    await db.vendor_suppliers.insert_one(supplier_doc)
    supplier_doc.pop("_id", None)
    return supplier_doc


@api_router.put("/vendor-suppliers/{supplier_id}")
async def update_vendor_supplier(
    supplier_id: str, data: VendorSupplierUpdate, user: dict = Depends(get_current_user)
):
    """Update a vendor supplier"""
    supplier = await db.vendor_suppliers.find_one({"supplier_id": supplier_id})
    if not supplier:
        raise HTTPException(status_code=404, detail="Vendor supplier not found")

    update_dict = {k: v for k, v in data.model_dump().items() if v is not None}
    if update_dict:
        update_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
        await db.vendor_suppliers.update_one(
            {"supplier_id": supplier_id}, {"$set": update_dict}
        )

    updated = await db.vendor_suppliers.find_one(
        {"supplier_id": supplier_id}, {"_id": 0}
    )
    return updated


@api_router.delete("/vendor-suppliers/{supplier_id}")
async def delete_vendor_supplier(
    supplier_id: str, user: dict = Depends(get_current_user)
):
    """Delete a vendor supplier"""
    # Check if there are linked income/expenses
    linked_entries = await db.income_expenses.count_documents(
        {"vendor_supplier_id": supplier_id}
    )
    if linked_entries > 0:
        # Soft delete - mark as inactive instead
        await db.vendor_suppliers.update_one(
            {"supplier_id": supplier_id},
            {
                "$set": {
                    "status": VendorSupplierStatus.INACTIVE,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        return {"message": "Supplier marked as inactive (has linked entries)"}

    result = await db.vendor_suppliers.delete_one({"supplier_id": supplier_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Vendor supplier not found")
    return {"message": "Supplier deleted"}


# ============== IE CATEGORIES (Account Categories) ROUTES ==============


@api_router.get("/ie-categories")
async def get_ie_categories(
    category_type: Optional[str] = None,
    active_only: bool = True,
    user: dict = Depends(get_current_user),
):
    """Get all income/expense account categories"""
    query = {}
    if category_type:
        query["$or"] = [{"category_type": category_type}, {"category_type": "both"}]
    if active_only:
        query["is_active"] = True

    categories = (
        await db.ie_categories.find(query, {"_id": 0}).sort("name", 1).to_list(500)
    )
    return categories


@api_router.get("/ie-categories/{category_id}")
async def get_ie_category(category_id: str, user: dict = Depends(get_current_user)):
    """Get a specific category"""
    category = await db.ie_categories.find_one({"category_id": category_id}, {"_id": 0})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")
    return category


@api_router.post("/ie-categories")
async def create_ie_category(
    data: IECategoryCreate, user: dict = Depends(get_current_user)
):
    """Create a new income/expense category"""
    # Check for duplicate name within same type
    existing = await db.ie_categories.find_one(
        {
            "name": {"$regex": f"^{data.name}$", "$options": "i"},
            "$or": [{"category_type": data.category_type}, {"category_type": "both"}],
        }
    )
    if existing:
        raise HTTPException(
            status_code=400, detail="A category with this name already exists"
        )

    category_id = f"iec_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    category_doc = {
        "category_id": category_id,
        "name": data.name,
        "category_type": data.category_type,
        "description": data.description,
        "parent_category_id": data.parent_category_id,
        "is_active": True,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "created_by": user["user_id"],
    }

    await db.ie_categories.insert_one(category_doc)
    category_doc.pop("_id", None)
    return category_doc


@api_router.put("/ie-categories/{category_id}")
async def update_ie_category(
    category_id: str, data: IECategoryUpdate, user: dict = Depends(get_current_user)
):
    """Update a category"""
    category = await db.ie_categories.find_one({"category_id": category_id})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    update_dict = {k: v for k, v in data.model_dump().items() if v is not None}
    if update_dict:
        update_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
        await db.ie_categories.update_one(
            {"category_id": category_id}, {"$set": update_dict}
        )

    updated = await db.ie_categories.find_one({"category_id": category_id}, {"_id": 0})
    return updated


@api_router.delete("/ie-categories/{category_id}")
async def delete_ie_category(category_id: str, user: dict = Depends(get_current_user)):
    """Delete a category (soft delete if linked to entries)"""
    # Check if there are linked income/expenses
    linked_entries = await db.income_expenses.count_documents(
        {"ie_category_id": category_id}
    )
    if linked_entries > 0:
        # Soft delete - mark as inactive
        await db.ie_categories.update_one(
            {"category_id": category_id},
            {
                "$set": {
                    "is_active": False,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        return {"message": "Category marked as inactive (has linked entries)"}

    result = await db.ie_categories.delete_one({"category_id": category_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"message": "Category deleted"}


# ============== LOAN MANAGEMENT ROUTES ==============

# === Static loan routes (MUST come before /{loan_id} route) ===


@api_router.get("/loans/dashboard")
async def get_loan_dashboard(user: dict = Depends(get_current_user)):
    """Get comprehensive loan dashboard data"""
    loans = await db.loans.find({}, {"_id": 0}).to_list(10000)
    now = datetime.now(timezone.utc)

    # Basic metrics
    total_disbursed_usd = 0
    total_outstanding_usd = 0
    total_repaid_usd = 0
    total_interest_earned = 0

    # Aging analysis
    aging = {
        "current": 0,
        "days_1_30": 0,
        "days_31_60": 0,
        "days_61_90": 0,
        "days_90_plus": 0,
    }

    # Status counts
    status_counts = {
        "active": 0,
        "partially_paid": 0,
        "fully_paid": 0,
        "overdue": 0,
        "written_off": 0,
    }

    # Loan type breakdown
    type_breakdown = {"short_term": 0, "long_term": 0, "credit_line": 0}

    # Top borrowers
    borrower_data = {}

    # Currency exposure
    currency_exposure = {}

    # Upcoming dues (next 30 days)
    upcoming_dues = []

    for loan in loans:
        amount_usd = loan.get(
            "amount_usd", convert_to_usd(loan["amount"], loan.get("currency", "USD"))
        )
        interest_usd = convert_to_usd(
            loan.get("total_interest", 0), loan.get("currency", "USD")
        )
        repaid_usd = convert_to_usd(
            loan.get("total_repaid", 0), loan.get("currency", "USD")
        )
        outstanding = amount_usd + interest_usd - repaid_usd

        total_disbursed_usd += amount_usd
        if outstanding > 0:
            total_outstanding_usd += outstanding
        total_repaid_usd += repaid_usd

        if loan.get("total_repaid", 0) > loan["amount"]:
            total_interest_earned += convert_to_usd(
                loan["total_repaid"] - loan["amount"], loan.get("currency", "USD")
            )

        # Status counts
        status = loan.get("status", "active")
        if status in status_counts:
            status_counts[status] += 1

        # Loan type
        loan_type = loan.get("loan_type", "short_term")
        if loan_type in type_breakdown:
            type_breakdown[loan_type] += amount_usd

        # Currency exposure
        currency = loan.get("currency", "USD")
        if currency not in currency_exposure:
            currency_exposure[currency] = {"amount": 0, "outstanding": 0, "count": 0}
        currency_exposure[currency]["amount"] += loan["amount"]
        currency_exposure[currency]["outstanding"] += max(
            0,
            loan["amount"]
            + loan.get("total_interest", 0)
            - loan.get("total_repaid", 0),
        )
        currency_exposure[currency]["count"] += 1

        # Top borrowers
        borrower = loan["borrower_name"]
        if borrower not in borrower_data:
            borrower_data[borrower] = {
                "total_disbursed": 0,
                "outstanding": 0,
                "loan_count": 0,
                "vendor_id": loan.get("vendor_id"),
            }
        borrower_data[borrower]["total_disbursed"] += amount_usd
        borrower_data[borrower]["outstanding"] += max(0, outstanding)
        borrower_data[borrower]["loan_count"] += 1

        # Aging analysis (for active/partially paid loans)
        if status in ["active", "partially_paid"] and loan.get("due_date"):
            due_str = loan["due_date"]
            try:
                if "T" in due_str:
                    due = datetime.fromisoformat(due_str.replace("Z", "+00:00"))
                else:
                    due = datetime.strptime(due_str[:10], "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                if due.tzinfo is None:
                    due = due.replace(tzinfo=timezone.utc)

                days_overdue = (now - due).days

                if days_overdue < 0:
                    aging["current"] += outstanding
                    # Check if due within 30 days
                    if days_overdue >= -30:
                        upcoming_dues.append(
                            {
                                "loan_id": loan["loan_id"],
                                "borrower": loan["borrower_name"],
                                "amount": loan["amount"],
                                "currency": loan.get("currency", "USD"),
                                "outstanding": outstanding,
                                "due_date": loan["due_date"],
                                "days_until_due": abs(days_overdue),
                            }
                        )
                elif days_overdue <= 30:
                    aging["days_1_30"] += outstanding
                elif days_overdue <= 60:
                    aging["days_31_60"] += outstanding
                elif days_overdue <= 90:
                    aging["days_61_90"] += outstanding
                else:
                    aging["days_90_plus"] += outstanding
            except:
                pass

    # Sort upcoming dues by days
    upcoming_dues.sort(key=lambda x: x["days_until_due"])

    # Top 5 borrowers by outstanding
    top_borrowers = sorted(
        borrower_data.items(), key=lambda x: x[1]["outstanding"], reverse=True
    )[:5]

    # Collection rate (this month)
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    this_month_repayments = await db.loan_repayments.find(
        {"payment_date": {"$gte": start_of_month.isoformat()}}, {"_id": 0}
    ).to_list(10000)

    this_month_collected = sum(
        convert_to_usd(r.get("amount", 0), r.get("currency", "USD"))
        for r in this_month_repayments
    )

    return {
        "portfolio_overview": {
            "total_disbursed_usd": round(total_disbursed_usd, 2),
            "total_outstanding_usd": round(total_outstanding_usd, 2),
            "total_repaid_usd": round(total_repaid_usd, 2),
            "total_interest_earned_usd": round(total_interest_earned, 2),
            "total_loans": len(loans),
        },
        "status_breakdown": status_counts,
        "loan_type_breakdown": {k: round(v, 2) for k, v in type_breakdown.items()},
        "aging_analysis": {k: round(v, 2) for k, v in aging.items()},
        "currency_exposure": currency_exposure,
        "top_borrowers": [
            {
                "name": k,
                **{
                    kk: round(vv, 2) if isinstance(vv, float) else vv
                    for kk, vv in v.items()
                },
            }
            for k, v in top_borrowers
        ],
        "upcoming_dues": upcoming_dues[:10],
        "collection_this_month": round(this_month_collected, 2),
    }


@api_router.get("/loans/transactions")
async def get_loan_transactions(
    loan_id: Optional[str] = None,
    transaction_type: Optional[str] = None,
    limit: int = 100,
    user: dict = Depends(get_current_user),
):
    """Get loan transactions log"""
    query = {}
    if loan_id:
        query["loan_id"] = loan_id
    if transaction_type:
        query["transaction_type"] = transaction_type

    transactions = (
        await db.loan_transactions.find(query, {"_id": 0})
        .sort("created_at", -1)
        .limit(limit)
        .to_list(limit)
    )
    return transactions


@api_router.get("/loans/vendors")
async def get_vendor_borrowers(user: dict = Depends(get_current_user)):
    """Get all vendors that can be borrowers with their loan stats"""
    vendors = await db.vendors.find({}, {"_id": 0}).to_list(1000)

    # Get loan stats for each vendor
    vendor_stats = {}
    loans = await db.loans.find(
        {},
        {
            "_id": 0,
            "vendor_id": 1,
            "amount": 1,
            "currency": 1,
            "total_repaid": 1,
            "total_interest": 1,
            "status": 1,
        },
    ).to_list(10000)

    for loan in loans:
        vid = loan.get("vendor_id")
        if vid:
            if vid not in vendor_stats:
                vendor_stats[vid] = {
                    "total_loans": 0,
                    "total_disbursed": 0,
                    "total_outstanding": 0,
                    "active_loans": 0,
                }

            amount_usd = convert_to_usd(loan["amount"], loan.get("currency", "USD"))
            outstanding = (
                loan["amount"]
                + loan.get("total_interest", 0)
                - loan.get("total_repaid", 0)
            )
            outstanding_usd = convert_to_usd(
                max(0, outstanding), loan.get("currency", "USD")
            )

            vendor_stats[vid]["total_loans"] += 1
            vendor_stats[vid]["total_disbursed"] += amount_usd
            vendor_stats[vid]["total_outstanding"] += outstanding_usd
            if loan["status"] in ["active", "partially_paid"]:
                vendor_stats[vid]["active_loans"] += 1

    # Combine vendor info with stats
    result = []
    for v in vendors:
        stats = vendor_stats.get(
            v["vendor_id"],
            {
                "total_loans": 0,
                "total_disbursed": 0,
                "total_outstanding": 0,
                "active_loans": 0,
            },
        )
        result.append(
            {
                "vendor_id": v["vendor_id"],
                "name": v.get("vendor_name") or v.get("name", "Unknown"),
                "email": v.get("email"),
                "status": v.get("status", "active"),
                "loan_stats": {
                    "total_loans": stats["total_loans"],
                    "total_disbursed_usd": round(stats["total_disbursed"], 2),
                    "total_outstanding_usd": round(stats["total_outstanding"], 2),
                    "active_loans": stats["active_loans"],
                },
            }
        )

    return result


# === List all loans ===


@api_router.get("/loans")
async def get_loans(
    status: Optional[str] = None,
    borrower: Optional[str] = None,
    limit: int = 100,
    user: dict = Depends(get_current_user),
):
    """Get all loans with optional filters"""
    query = {}
    if status:
        query["status"] = status
    if borrower:
        query["borrower_name"] = {"$regex": borrower, "$options": "i"}

    loans = (
        await db.loans.find(query, {"_id": 0})
        .sort("created_at", -1)
        .limit(limit)
        .to_list(limit)
    )

    # Batch fetch treasury accounts to avoid N+1 queries
    treasury_ids = list(
        set(
            loan.get("source_treasury_id")
            for loan in loans
            if loan.get("source_treasury_id")
        )
    )
    treasury_map = {}
    if treasury_ids:
        treasuries = await db.treasury_accounts.find(
            {"account_id": {"$in": treasury_ids}}, {"_id": 0}
        ).to_list(len(treasury_ids))
        treasury_map = {t["account_id"]: t["account_name"] for t in treasuries}

    # Process loans
    for loan in loans:
        if loan.get("source_treasury_id"):
            loan["source_treasury_name"] = treasury_map.get(
                loan["source_treasury_id"], "Unknown"
            )

        # Calculate outstanding balance
        loan["outstanding_balance"] = (
            loan["amount"] + loan.get("total_interest", 0) - loan.get("total_repaid", 0)
        )

        # Check if overdue
        if loan["status"] == LoanStatus.ACTIVE:
            if loan.get("due_date"):
                due_str = loan["due_date"]
                try:
                    if "T" in due_str:
                        due = datetime.fromisoformat(due_str.replace("Z", "+00:00"))
                    else:
                        due = datetime.strptime(due_str[:10], "%Y-%m-%d").replace(
                            tzinfo=timezone.utc
                        )
                    if due.tzinfo is None:
                        due = due.replace(tzinfo=timezone.utc)
                    if due < datetime.now(timezone.utc):
                        loan["is_overdue"] = True
                except (ValueError, TypeError):
                    # Invalid date format - skip overdue check
                    loan["is_overdue"] = False

    return loans


@api_router.get("/loans/{loan_id}")
async def get_loan(loan_id: str, user: dict = Depends(get_current_user)):
    """Get a single loan with repayment history"""
    loan = await db.loans.find_one({"loan_id": loan_id}, {"_id": 0})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")

    # Get treasury account name
    if loan.get("source_treasury_id"):
        acc = await db.treasury_accounts.find_one(
            {"account_id": loan["source_treasury_id"]}, {"_id": 0}
        )
        loan["source_treasury_name"] = acc["account_name"] if acc else "Unknown"

    # Get repayment history
    repayments = (
        await db.loan_repayments.find({"loan_id": loan_id}, {"_id": 0})
        .sort("payment_date", -1)
        .to_list(1000)
    )
    for rep in repayments:
        if rep.get("treasury_account_id"):
            acc = await db.treasury_accounts.find_one(
                {"account_id": rep["treasury_account_id"]}, {"_id": 0}
            )
            rep["treasury_account_name"] = acc["account_name"] if acc else "Unknown"

    loan["repayments"] = repayments
    loan["outstanding_balance"] = (
        loan["amount"] + loan.get("total_interest", 0) - loan.get("total_repaid", 0)
    )

    return loan


@api_router.post("/loans")
async def create_loan(loan_data: LoanCreate, user: dict = Depends(get_current_user)):
    """Create a new loan and deduct from treasury"""
    # Verify treasury account exists and has sufficient balance
    treasury = await db.treasury_accounts.find_one(
        {"account_id": loan_data.treasury_account_id}, {"_id": 0}
    )
    if not treasury:
        raise HTTPException(status_code=404, detail="Treasury account not found")

    if treasury.get("balance", 0) < loan_data.amount:
        raise HTTPException(
            status_code=400, detail="Insufficient balance in treasury account"
        )

    if loan_data.amount <= 0:
        raise HTTPException(status_code=400, detail="Loan amount must be positive")

    # If vendor_id provided, get vendor details
    vendor = None
    if loan_data.vendor_id:
        vendor = await db.vendors.find_one(
            {"vendor_id": loan_data.vendor_id}, {"_id": 0}
        )

    loan_id = f"loan_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # Calculate interest (simple interest)
    # Interest = Principal * Rate * Time (in years)
    loan_date = datetime.fromisoformat(loan_data.loan_date.replace("Z", "+00:00"))
    due_date = datetime.fromisoformat(loan_data.due_date.replace("Z", "+00:00"))
    days_diff = (due_date - loan_date).days
    years = days_diff / 365
    total_interest = round(
        loan_data.amount * (loan_data.interest_rate / 100) * years, 2
    )

    # Calculate USD equivalent
    amount_usd = convert_to_usd(loan_data.amount, loan_data.currency)

    loan_doc = {
        "loan_id": loan_id,
        "vendor_id": loan_data.vendor_id,
        "vendor_name": (
            vendor.get("vendor_name") or vendor.get("name") if vendor else None
        ),
        "borrower_name": loan_data.borrower_name,
        "amount": loan_data.amount,
        "currency": loan_data.currency,
        "amount_usd": amount_usd,
        "interest_rate": loan_data.interest_rate,
        "loan_type": loan_data.loan_type,
        "total_interest": total_interest,
        "loan_date": loan_data.loan_date,
        "due_date": loan_data.due_date,
        "repayment_mode": loan_data.repayment_mode,
        "installment_amount": loan_data.installment_amount,
        "installment_frequency": loan_data.installment_frequency,
        "num_installments": loan_data.num_installments,
        "collateral": loan_data.collateral,
        "source_treasury_id": loan_data.treasury_account_id,
        "total_repaid": 0,
        "repayment_count": 0,
        "status": LoanStatus.ACTIVE,
        "notes": loan_data.notes,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.loans.insert_one(loan_doc)

    # Deduct from treasury account - convert if currencies differ
    treasury_currency = treasury.get("currency", "USD")
    treasury_deduct_amount = loan_data.amount
    if treasury_currency.upper() != loan_data.currency.upper():
        treasury_deduct_amount = convert_currency(
            loan_data.amount, loan_data.currency, treasury_currency
        )

    await db.treasury_accounts.update_one(
        {"account_id": loan_data.treasury_account_id},
        {
            "$inc": {"balance": -treasury_deduct_amount},
            "$set": {"updated_at": now.isoformat()},
        },
    )

    # Record treasury transaction
    conversion_note = (
        f" (Converted from {loan_data.amount:,.2f} {loan_data.currency})"
        if treasury_currency.upper() != loan_data.currency.upper()
        else ""
    )
    tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
    tx_doc = {
        "treasury_transaction_id": tx_id,
        "account_id": loan_data.treasury_account_id,
        "transaction_type": "loan_disbursement",
        "amount": -treasury_deduct_amount,
        "currency": treasury_currency,
        "original_amount": loan_data.amount,
        "original_currency": loan_data.currency,
        "reference": f"Loan to {loan_data.borrower_name}{conversion_note}",
        "loan_id": loan_id,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.treasury_transactions.insert_one(tx_doc)

    # Record loan transaction
    await db.loan_transactions.insert_one(
        {
            "transaction_id": f"ltx_{uuid.uuid4().hex[:12]}",
            "loan_id": loan_id,
            "transaction_type": LoanTransactionType.DISBURSEMENT,
            "amount": loan_data.amount,
            "currency": loan_data.currency,
            "treasury_account_id": loan_data.treasury_account_id,
            "description": f"Loan disbursement to {loan_data.borrower_name}",
            "created_at": now.isoformat(),
            "created_by": user["user_id"],
            "created_by_name": user["name"],
        }
    )

    loan_doc.pop("_id", None)
    loan_doc["source_treasury_name"] = treasury["account_name"]
    loan_doc["outstanding_balance"] = loan_data.amount + total_interest
    return loan_doc


@api_router.put("/loans/{loan_id}")
async def update_loan(
    loan_id: str, update_data: LoanUpdate, user: dict = Depends(get_current_user)
):
    """Update loan details (not amount)"""
    loan = await db.loans.find_one({"loan_id": loan_id}, {"_id": 0})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")

    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not update_dict:
        raise HTTPException(status_code=400, detail="No fields to update")

    update_dict["updated_at"] = datetime.now(timezone.utc).isoformat()

    await db.loans.update_one({"loan_id": loan_id}, {"$set": update_dict})

    updated = await db.loans.find_one({"loan_id": loan_id}, {"_id": 0})
    return updated


@api_router.post("/loans/{loan_id}/repayment")
async def record_loan_repayment(
    loan_id: str, repayment: LoanRepaymentCreate, user: dict = Depends(get_current_user)
):
    """Record a loan repayment"""
    loan = await db.loans.find_one({"loan_id": loan_id}, {"_id": 0})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")

    if loan["status"] == LoanStatus.FULLY_PAID:
        raise HTTPException(status_code=400, detail="Loan is already fully paid")

    # Verify treasury account exists
    treasury = await db.treasury_accounts.find_one(
        {"account_id": repayment.treasury_account_id}, {"_id": 0}
    )
    if not treasury:
        raise HTTPException(status_code=404, detail="Treasury account not found")

    if repayment.amount <= 0:
        raise HTTPException(status_code=400, detail="Repayment amount must be positive")

    repayment_id = f"rep_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    payment_date = (
        repayment.payment_date if repayment.payment_date else now.isoformat()[:10]
    )

    # Convert to loan currency if different
    repayment_amount_in_loan_currency = repayment.amount
    exchange_rate_used = 1.0
    if repayment.currency != loan["currency"]:
        if repayment.amount_in_loan_currency and repayment.amount_in_loan_currency > 0:
            # Use pre-calculated amount from frontend
            repayment_amount_in_loan_currency = repayment.amount_in_loan_currency
            exchange_rate_used = repayment.exchange_rate or (
                repayment_amount_in_loan_currency / repayment.amount
                if repayment.amount
                else 1.0
            )
        elif repayment.exchange_rate and repayment.exchange_rate > 0:
            # Use provided exchange rate (payment currency -> loan currency)
            repayment_amount_in_loan_currency = round(
                repayment.amount * repayment.exchange_rate, 2
            )
            exchange_rate_used = repayment.exchange_rate
        else:
            # Convert using live FX rates
            amount_usd = convert_to_usd(repayment.amount, repayment.currency)
            loan_rate = EXCHANGE_RATES_TO_USD.get(loan["currency"].upper(), 1.0)
            repayment_amount_in_loan_currency = (
                round(amount_usd / loan_rate, 2) if loan_rate else repayment.amount
            )
            exchange_rate_used = (
                round(repayment_amount_in_loan_currency / repayment.amount, 6)
                if repayment.amount
                else 1.0
            )

    repayment_doc = {
        "repayment_id": repayment_id,
        "loan_id": loan_id,
        "amount": repayment.amount,
        "currency": repayment.currency,
        "amount_in_loan_currency": repayment_amount_in_loan_currency,
        "loan_currency": loan["currency"],
        "exchange_rate": exchange_rate_used,
        "treasury_account_id": repayment.treasury_account_id,
        "payment_date": payment_date,
        "reference": repayment.reference,
        "notes": repayment.notes,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.loan_repayments.insert_one(repayment_doc)

    # Update loan totals
    new_total_repaid = loan.get("total_repaid", 0) + repayment_amount_in_loan_currency
    outstanding = loan["amount"] + loan.get("total_interest", 0) - new_total_repaid

    # Determine new status
    new_status = loan["status"]
    if outstanding <= 0:
        new_status = LoanStatus.FULLY_PAID
    elif new_total_repaid > 0:
        new_status = LoanStatus.PARTIALLY_PAID

    await db.loans.update_one(
        {"loan_id": loan_id},
        {
            "$set": {
                "total_repaid": new_total_repaid,
                "outstanding_balance": max(0, outstanding),
                "status": new_status,
                "updated_at": now.isoformat(),
            },
            "$inc": {"repayment_count": 1},
        },
    )

    # Credit treasury account - convert if currency differs
    treasury_currency = treasury.get("currency", "USD")
    treasury_credit_amount = repayment.amount
    if treasury_currency.upper() != repayment.currency.upper():
        treasury_credit_amount = convert_currency(
            repayment.amount, repayment.currency, treasury_currency
        )

    await db.treasury_accounts.update_one(
        {"account_id": repayment.treasury_account_id},
        {
            "$inc": {"balance": treasury_credit_amount},
            "$set": {"updated_at": now.isoformat()},
        },
    )

    # Record treasury transaction
    conversion_note = (
        f" (Converted from {repayment.amount:,.2f} {repayment.currency})"
        if treasury_currency.upper() != repayment.currency.upper()
        else ""
    )
    tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
    tx_doc = {
        "treasury_transaction_id": tx_id,
        "account_id": repayment.treasury_account_id,
        "transaction_type": "loan_repayment",
        "amount": treasury_credit_amount,
        "currency": treasury_currency,
        "original_amount": repayment.amount,
        "original_currency": repayment.currency,
        "reference": f"Loan repayment from {loan['borrower_name']}{conversion_note}",
        "loan_id": loan_id,
        "repayment_id": repayment_id,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.treasury_transactions.insert_one(tx_doc)

    # Record loan transaction
    await db.loan_transactions.insert_one(
        {
            "transaction_id": f"ltx_{uuid.uuid4().hex[:12]}",
            "loan_id": loan_id,
            "transaction_type": LoanTransactionType.REPAYMENT,
            "amount": repayment.amount,
            "currency": repayment.currency,
            "treasury_account_id": repayment.treasury_account_id,
            "description": f"Repayment from {loan['borrower_name']}",
            "created_at": now.isoformat(),
            "created_by": user["user_id"],
            "created_by_name": user["name"],
        }
    )

    repayment_doc.pop("_id", None)
    repayment_doc["treasury_account_name"] = treasury["account_name"]
    repayment_doc["new_outstanding"] = max(0, outstanding)
    repayment_doc["loan_status"] = new_status
    return repayment_doc


@api_router.get("/loans/{loan_id}/repayments")
async def get_loan_repayments(loan_id: str, user: dict = Depends(get_current_user)):
    """Get repayment history for a loan"""
    loan = await db.loans.find_one({"loan_id": loan_id}, {"_id": 0})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")

    repayments = (
        await db.loan_repayments.find({"loan_id": loan_id}, {"_id": 0})
        .sort("payment_date", -1)
        .to_list(1000)
    )

    for rep in repayments:
        if rep.get("treasury_account_id"):
            acc = await db.treasury_accounts.find_one(
                {"account_id": rep["treasury_account_id"]}, {"_id": 0}
            )
            rep["treasury_account_name"] = acc["account_name"] if acc else "Unknown"

    return repayments


@api_router.delete("/loans/{loan_id}")
async def delete_loan(loan_id: str, user: dict = Depends(require_admin)):
    """Delete a loan (admin only) - reverses treasury if no repayments"""
    loan = await db.loans.find_one({"loan_id": loan_id}, {"_id": 0})
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")

    # Check if there are repayments
    repayment_count = await db.loan_repayments.count_documents({"loan_id": loan_id})
    if repayment_count > 0:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete loan with repayments. Delete repayments first.",
        )

    now = datetime.now(timezone.utc)

    # Reverse treasury balance (credit back the loan amount)
    await db.treasury_accounts.update_one(
        {"account_id": loan["source_treasury_id"]},
        {"$inc": {"balance": loan["amount"]}, "$set": {"updated_at": now.isoformat()}},
    )

    # Delete the loan
    await db.loans.delete_one({"loan_id": loan_id})

    # Delete related treasury transaction
    await db.treasury_transactions.delete_one({"loan_id": loan_id})

    return {"message": "Loan deleted successfully"}


@api_router.get("/loans/reports/summary")
async def get_loans_summary(user: dict = Depends(get_current_user)):
    """Get loan portfolio summary"""
    loans = await db.loans.find({}, {"_id": 0}).to_list(10000)

    total_disbursed = 0
    total_outstanding = 0
    total_repaid = 0
    total_interest_expected = 0
    total_interest_earned = 0

    active_count = 0
    partially_paid_count = 0
    fully_paid_count = 0
    overdue_count = 0

    by_borrower = {}

    for loan in loans:
        amount_usd = loan.get(
            "amount_usd", convert_to_usd(loan["amount"], loan["currency"])
        )
        interest_usd = convert_to_usd(loan.get("total_interest", 0), loan["currency"])
        repaid_usd = convert_to_usd(loan.get("total_repaid", 0), loan["currency"])

        total_disbursed += amount_usd
        total_interest_expected += interest_usd
        total_repaid += repaid_usd

        outstanding = amount_usd + interest_usd - repaid_usd
        if outstanding > 0:
            total_outstanding += outstanding

        # Interest earned is the interest portion of repayments
        if loan.get("total_repaid", 0) > loan["amount"]:
            total_interest_earned += convert_to_usd(
                loan["total_repaid"] - loan["amount"], loan["currency"]
            )

        # Count by status
        if loan["status"] == LoanStatus.ACTIVE:
            active_count += 1
            # Check if overdue
            if loan.get("due_date"):
                due_str = loan["due_date"]
                if "T" in due_str:
                    due = datetime.fromisoformat(due_str.replace("Z", "+00:00"))
                else:
                    # Date only string like "2026-03-15"
                    due = datetime.strptime(due_str[:10], "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                if due.tzinfo is None:
                    due = due.replace(tzinfo=timezone.utc)
                if due < datetime.now(timezone.utc):
                    overdue_count += 1
        elif loan["status"] == LoanStatus.PARTIALLY_PAID:
            partially_paid_count += 1
        elif loan["status"] == LoanStatus.FULLY_PAID:
            fully_paid_count += 1

        # Group by borrower
        borrower = loan["borrower_name"]
        if borrower not in by_borrower:
            by_borrower[borrower] = {"disbursed": 0, "outstanding": 0, "count": 0}
        by_borrower[borrower]["disbursed"] += amount_usd
        by_borrower[borrower]["outstanding"] += max(0, outstanding)
        by_borrower[borrower]["count"] += 1

    return {
        "total_loans": len(loans),
        "total_disbursed_usd": round(total_disbursed, 2),
        "total_outstanding_usd": round(total_outstanding, 2),
        "total_repaid_usd": round(total_repaid, 2),
        "total_interest_expected_usd": round(total_interest_expected, 2),
        "total_interest_earned_usd": round(total_interest_earned, 2),
        "status_breakdown": {
            "active": active_count,
            "partially_paid": partially_paid_count,
            "fully_paid": fully_paid_count,
            "overdue": overdue_count,
        },
        "by_borrower": {
            k: {
                **v,
                "disbursed": round(v["disbursed"], 2),
                "outstanding": round(v["outstanding"], 2),
            }
            for k, v in by_borrower.items()
        },
    }


@api_router.get("/loans/export/csv")
async def export_loans_csv(user: dict = Depends(get_current_user)):
    """Export all loans as CSV"""
    from io import StringIO
    import csv

    loans = await db.loans.find({}, {"_id": 0}).sort("loan_date", -1).to_list(50000)

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Loan ID",
            "Borrower",
            "Amount",
            "Currency",
            "Interest Rate (%)",
            "Loan Date",
            "Due Date",
            "Outstanding Balance",
            "Total Repaid",
            "Status",
            "Repayment Mode",
            "Notes",
            "Created At",
        ]
    )

    for loan in loans:
        writer.writerow(
            [
                loan.get("loan_id", ""),
                loan.get("borrower_name", ""),
                loan.get("amount", 0),
                loan.get("currency", "USD"),
                loan.get("interest_rate", 0),
                loan.get("loan_date", ""),
                loan.get("due_date", ""),
                loan.get("outstanding_balance", 0),
                loan.get("total_repaid", 0),
                loan.get("status", ""),
                loan.get("repayment_mode", ""),
                loan.get("notes", ""),
                loan.get("created_at", ""),
            ]
        )

    from fastapi.responses import StreamingResponse

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=loans_export.csv"},
    )


# ============== DEBT MANAGEMENT ==============


class DebtType:
    RECEIVABLE = "receivable"  # Money owed TO us (Debtors)
    PAYABLE = "payable"  # Money owed BY us (Creditors)


class DebtStatus:
    PENDING = "pending"
    PARTIALLY_PAID = "partially_paid"
    FULLY_PAID = "fully_paid"
    OVERDUE = "overdue"


class DebtPartyType:
    CLIENT = "client"
    VENDOR = "vendor"
    OTHER = "other"


class DebtCreate(BaseModel):
    debt_type: str  # receivable or payable
    party_type: str  # client, vendor, or other
    party_id: Optional[str] = None  # client_id or vendor_id if linked
    party_name: str  # Name (auto-filled if linked, manual if other)
    amount: float
    currency: str = "USD"
    due_date: str  # ISO date
    interest_rate: float = 0  # Annual interest rate for overdue
    description: Optional[str] = None
    reference: Optional[str] = None
    treasury_account_id: Optional[str] = None  # For tracking payments


class DebtUpdate(BaseModel):
    party_name: Optional[str] = None
    amount: Optional[float] = None
    due_date: Optional[str] = None
    interest_rate: Optional[float] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    status: Optional[str] = None


class DebtPaymentCreate(BaseModel):
    amount: float
    currency: str = "USD"
    payment_date: Optional[str] = None
    treasury_account_id: str
    reference: Optional[str] = None
    notes: Optional[str] = None


def calculate_debt_interest(
    principal: float, annual_rate: float, days_overdue: int
) -> float:
    """Calculate simple interest on overdue debt"""
    if days_overdue <= 0 or annual_rate <= 0:
        return 0
    daily_rate = annual_rate / 100 / 365
    return round(principal * daily_rate * days_overdue, 2)


def get_debt_status(debt: dict) -> str:
    """Calculate current debt status based on payments and due date"""
    total_paid = debt.get("total_paid", 0)
    amount = debt.get("amount", 0)
    due_date_str = debt.get("due_date")

    if total_paid >= amount:
        return DebtStatus.FULLY_PAID

    if due_date_str:
        try:
            due_date = datetime.fromisoformat(due_date_str.replace("Z", "+00:00"))
            if due_date.tzinfo is None:
                due_date = due_date.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > due_date and total_paid < amount:
                return DebtStatus.OVERDUE
        except:
            pass

    if total_paid > 0:
        return DebtStatus.PARTIALLY_PAID

    return DebtStatus.PENDING


@api_router.get("/debts")
async def get_debts(
    user: dict = Depends(get_current_user),
    debt_type: Optional[str] = None,
    status: Optional[str] = None,
    party_type: Optional[str] = None,
):
    """Get all debts with calculated interest and status"""
    query = {}
    if debt_type:
        query["debt_type"] = debt_type
    if party_type:
        query["party_type"] = party_type

    debts = await db.debts.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    now = datetime.now(timezone.utc)

    for debt in debts:
        # Calculate current status
        debt["calculated_status"] = get_debt_status(debt)

        # Calculate days overdue and interest
        due_date_str = debt.get("due_date")
        if due_date_str:
            try:
                due_date = datetime.fromisoformat(due_date_str.replace("Z", "+00:00"))
                if due_date.tzinfo is None:
                    due_date = due_date.replace(tzinfo=timezone.utc)

                if now > due_date:
                    debt["days_overdue"] = (now - due_date).days
                    outstanding = debt.get("amount", 0) - debt.get("total_paid", 0)
                    debt["accrued_interest"] = calculate_debt_interest(
                        outstanding, debt.get("interest_rate", 0), debt["days_overdue"]
                    )
                else:
                    debt["days_overdue"] = 0
                    debt["accrued_interest"] = 0
                    debt["days_until_due"] = (due_date - now).days
            except:
                debt["days_overdue"] = 0
                debt["accrued_interest"] = 0

        # Calculate outstanding balance
        debt["outstanding_balance"] = debt.get("amount", 0) - debt.get("total_paid", 0)
        debt["total_due"] = debt["outstanding_balance"] + debt.get(
            "accrued_interest", 0
        )

    # Filter by status if requested (after calculation)
    if status:
        debts = [d for d in debts if d.get("calculated_status") == status]

    return debts


@api_router.get("/debts/{debt_id}")
async def get_debt(debt_id: str, user: dict = Depends(get_current_user)):
    """Get single debt with full details and payment history"""
    debt = await db.debts.find_one({"debt_id": debt_id}, {"_id": 0})
    if not debt:
        raise HTTPException(status_code=404, detail="Debt not found")

    now = datetime.now(timezone.utc)

    # Calculate status and interest
    debt["calculated_status"] = get_debt_status(debt)

    due_date_str = debt.get("due_date")
    if due_date_str:
        try:
            due_date = datetime.fromisoformat(due_date_str.replace("Z", "+00:00"))
            if due_date.tzinfo is None:
                due_date = due_date.replace(tzinfo=timezone.utc)

            if now > due_date:
                debt["days_overdue"] = (now - due_date).days
                outstanding = debt.get("amount", 0) - debt.get("total_paid", 0)
                debt["accrued_interest"] = calculate_debt_interest(
                    outstanding, debt.get("interest_rate", 0), debt["days_overdue"]
                )
            else:
                debt["days_overdue"] = 0
                debt["accrued_interest"] = 0
                debt["days_until_due"] = (due_date - now).days
        except:
            debt["days_overdue"] = 0
            debt["accrued_interest"] = 0

    debt["outstanding_balance"] = debt.get("amount", 0) - debt.get("total_paid", 0)
    debt["total_due"] = debt["outstanding_balance"] + debt.get("accrued_interest", 0)

    # Get payment history
    payments = (
        await db.debt_payments.find({"debt_id": debt_id}, {"_id": 0})
        .sort("payment_date", -1)
        .to_list(100)
    )
    debt["payments"] = payments

    return debt


@api_router.post("/debts")
async def create_debt(debt_data: DebtCreate, user: dict = Depends(get_current_user)):
    """Create a new debt record"""
    debt_id = f"debt_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # If linked to client/vendor, verify and get name
    party_name = debt_data.party_name
    if debt_data.party_type == DebtPartyType.CLIENT and debt_data.party_id:
        client = await db.clients.find_one(
            {"client_id": debt_data.party_id}, {"_id": 0}
        )
        if client:
            party_name = (
                f"{client.get('first_name', '')} {client.get('last_name', '')}".strip()
            )
    elif debt_data.party_type == DebtPartyType.VENDOR and debt_data.party_id:
        vendor = await db.vendors.find_one(
            {"vendor_id": debt_data.party_id}, {"_id": 0}
        )
        if vendor:
            party_name = vendor.get("vendor_name", party_name)

    debt_doc = {
        "debt_id": debt_id,
        "debt_type": debt_data.debt_type,
        "party_type": debt_data.party_type,
        "party_id": debt_data.party_id,
        "party_name": party_name,
        "amount": debt_data.amount,
        "currency": debt_data.currency,
        "amount_usd": convert_to_usd(debt_data.amount, debt_data.currency),
        "due_date": debt_data.due_date,
        "interest_rate": debt_data.interest_rate,
        "description": debt_data.description,
        "reference": debt_data.reference,
        "treasury_account_id": debt_data.treasury_account_id,
        "total_paid": 0,
        "total_paid_usd": 0,
        "payment_count": 0,
        "status": DebtStatus.PENDING,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.debts.insert_one(debt_doc)
    return await db.debts.find_one({"debt_id": debt_id}, {"_id": 0})


@api_router.put("/debts/{debt_id}")
async def update_debt(
    debt_id: str, update_data: DebtUpdate, user: dict = Depends(get_current_user)
):
    """Update a debt record"""
    debt = await db.debts.find_one({"debt_id": debt_id}, {"_id": 0})
    if not debt:
        raise HTTPException(status_code=404, detail="Debt not found")

    updates = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    # Recalculate USD if amount changed
    if "amount" in updates:
        updates["amount_usd"] = convert_to_usd(
            updates["amount"], debt.get("currency", "USD")
        )

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    await db.debts.update_one({"debt_id": debt_id}, {"$set": updates})
    return await db.debts.find_one({"debt_id": debt_id}, {"_id": 0})


@api_router.delete("/debts/{debt_id}")
async def delete_debt(debt_id: str, user: dict = Depends(require_admin)):
    """Delete a debt record (admin only)"""
    debt = await db.debts.find_one({"debt_id": debt_id}, {"_id": 0})
    if not debt:
        raise HTTPException(status_code=404, detail="Debt not found")

    if debt.get("total_paid", 0) > 0:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete debt with payments. Mark as cancelled instead.",
        )

    await db.debts.delete_one({"debt_id": debt_id})
    return {"message": "Debt deleted"}


@api_router.post("/debts/{debt_id}/payments")
async def record_debt_payment(
    debt_id: str,
    payment_data: DebtPaymentCreate,
    user: dict = Depends(get_current_user),
):
    """Record a payment against a debt"""
    debt = await db.debts.find_one({"debt_id": debt_id}, {"_id": 0})
    if not debt:
        raise HTTPException(status_code=404, detail="Debt not found")

    # Verify treasury account
    treasury = await db.treasury_accounts.find_one(
        {"account_id": payment_data.treasury_account_id}, {"_id": 0}
    )
    if not treasury:
        raise HTTPException(status_code=404, detail="Treasury account not found")

    payment_id = f"dpay_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    payment_date = payment_data.payment_date or now.isoformat()

    # Convert payment to USD
    payment_usd = convert_to_usd(payment_data.amount, payment_data.currency)

    # Convert payment amount to treasury currency for balance update
    treasury_currency = treasury.get("currency", "USD")
    if payment_data.currency == treasury_currency:
        amount_in_treasury_currency = payment_data.amount
    else:
        # Convert payment to treasury currency via USD
        amount_in_treasury_currency = convert_from_usd(payment_usd, treasury_currency)

    payment_doc = {
        "payment_id": payment_id,
        "debt_id": debt_id,
        "debt_type": debt["debt_type"],
        "party_name": debt.get("party_name"),
        "amount": payment_data.amount,
        "currency": payment_data.currency,
        "amount_usd": payment_usd,
        "amount_in_treasury_currency": amount_in_treasury_currency,
        "treasury_currency": treasury_currency,
        "payment_date": payment_date,
        "treasury_account_id": payment_data.treasury_account_id,
        "treasury_account_name": treasury.get("account_name"),
        "reference": payment_data.reference,
        "notes": payment_data.notes,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }

    await db.debt_payments.insert_one(payment_doc)

    # Determine balance change direction
    if debt["debt_type"] == DebtType.RECEIVABLE:
        # We received money - increase treasury (positive)
        balance_change = amount_in_treasury_currency
        tx_type = "debt_collection"
        tx_description = f"Debt collection from {debt.get('party_name', 'Unknown')}"
    else:
        # We paid money (creditor/payable) - decrease treasury (negative)
        balance_change = -amount_in_treasury_currency
        tx_type = "debt_payment"
        tx_description = f"Debt payment to {debt.get('party_name', 'Unknown')}"

    # Update treasury balance
    await db.treasury_accounts.update_one(
        {"account_id": payment_data.treasury_account_id},
        {"$inc": {"balance": balance_change}, "$set": {"updated_at": now.isoformat()}},
    )

    # Record treasury transaction for history
    treasury_tx_id = f"ttx_{uuid.uuid4().hex[:12]}"
    treasury_tx = {
        "transaction_id": treasury_tx_id,
        "account_id": payment_data.treasury_account_id,
        "account_name": treasury.get("account_name"),
        "transaction_type": tx_type,
        "amount": abs(amount_in_treasury_currency),
        "currency": treasury_currency,
        "amount_usd": payment_usd,
        "balance_after": treasury.get("balance", 0) + balance_change,
        "description": tx_description,
        "reference": payment_data.reference or payment_id,
        "related_debt_id": debt_id,
        "related_payment_id": payment_id,
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.treasury_transactions.insert_one(treasury_tx)

    # AUTO-CREATE INCOME/EXPENSE ENTRY
    # Receivable payment → Income entry
    # Payable payment → Expense entry
    ie_entry_id = f"ie_{uuid.uuid4().hex[:12]}"
    if debt["debt_type"] == DebtType.RECEIVABLE:
        # Create Income entry when collecting receivable
        income_entry = {
            "entry_id": ie_entry_id,
            "entry_type": "income",
            "category": "Debt Collection",
            "amount": payment_usd,  # Store in USD
            "currency": "USD",
            "date": (
                payment_date.split("T")[0] if "T" in str(payment_date) else payment_date
            ),
            "description": f"Collection from {debt.get('party_name', 'Unknown')} - {debt.get('description', '')}".strip(),
            "reference": payment_data.reference or payment_id,
            "treasury_account_id": payment_data.treasury_account_id,
            "related_debt_id": debt_id,
            "related_payment_id": payment_id,
            "auto_generated": True,
            "created_at": now.isoformat(),
            "created_by": user["user_id"],
            "created_by_name": user["name"],
        }
        await db.income_expenses.insert_one(income_entry)
    else:
        # Create Expense entry when paying payable
        expense_entry = {
            "entry_id": ie_entry_id,
            "entry_type": "expense",
            "category": "Debt Payment",
            "amount": payment_usd,  # Store in USD
            "currency": "USD",
            "date": (
                payment_date.split("T")[0] if "T" in str(payment_date) else payment_date
            ),
            "description": f"Payment to {debt.get('party_name', 'Unknown')} - {debt.get('description', '')}".strip(),
            "reference": payment_data.reference or payment_id,
            "treasury_account_id": payment_data.treasury_account_id,
            "related_debt_id": debt_id,
            "related_payment_id": payment_id,
            "auto_generated": True,
            "created_at": now.isoformat(),
            "created_by": user["user_id"],
            "created_by_name": user["name"],
        }
        await db.income_expenses.insert_one(expense_entry)

    # Update debt totals
    new_total_paid = debt.get("total_paid", 0) + payment_data.amount
    new_total_paid_usd = debt.get("total_paid_usd", 0) + payment_usd
    new_payment_count = debt.get("payment_count", 0) + 1

    # Determine new status
    new_status = DebtStatus.PARTIALLY_PAID
    if new_total_paid >= debt["amount"]:
        new_status = DebtStatus.FULLY_PAID

    await db.debts.update_one(
        {"debt_id": debt_id},
        {
            "$set": {
                "total_paid": new_total_paid,
                "total_paid_usd": new_total_paid_usd,
                "payment_count": new_payment_count,
                "status": new_status,
                "updated_at": now.isoformat(),
                "last_payment_date": payment_date,
            }
        },
    )

    return await db.debts.find_one({"debt_id": debt_id}, {"_id": 0})


@api_router.get("/debts/{debt_id}/payments")
async def get_debt_payments(debt_id: str, user: dict = Depends(get_current_user)):
    """Get all payments for a debt"""
    payments = (
        await db.debt_payments.find({"debt_id": debt_id}, {"_id": 0})
        .sort("payment_date", -1)
        .to_list(100)
    )
    return payments


@api_router.get("/debts/summary/overview")
async def get_debts_summary(user: dict = Depends(get_current_user)):
    """Get summary of all debts"""
    now = datetime.now(timezone.utc)

    # Get all debts
    debts = await db.debts.find({}, {"_id": 0}).to_list(10000)

    summary = {
        "receivables": {
            "total_amount": 0,
            "total_paid": 0,
            "outstanding": 0,
            "overdue_amount": 0,
            "accrued_interest": 0,
            "count": 0,
            "overdue_count": 0,
        },
        "payables": {
            "total_amount": 0,
            "total_paid": 0,
            "outstanding": 0,
            "overdue_amount": 0,
            "accrued_interest": 0,
            "count": 0,
            "overdue_count": 0,
        },
        "aging": {
            "current": 0,
            "days_1_30": 0,
            "days_31_60": 0,
            "days_61_90": 0,
            "days_over_90": 0,
        },
    }

    for debt in debts:
        debt_type = debt.get("debt_type", "receivable")
        category = "receivables" if debt_type == "receivable" else "payables"
        amount_usd = debt.get(
            "amount_usd",
            convert_to_usd(debt.get("amount", 0), debt.get("currency", "USD")),
        )
        paid_usd = debt.get("total_paid_usd", 0)
        outstanding = amount_usd - paid_usd

        summary[category]["total_amount"] += amount_usd
        summary[category]["total_paid"] += paid_usd
        summary[category]["outstanding"] += outstanding
        summary[category]["count"] += 1

        # Check if overdue
        due_date_str = debt.get("due_date")
        if due_date_str and outstanding > 0:
            try:
                due_date = datetime.fromisoformat(due_date_str.replace("Z", "+00:00"))
                if due_date.tzinfo is None:
                    due_date = due_date.replace(tzinfo=timezone.utc)

                if now > due_date:
                    days_overdue = (now - due_date).days
                    summary[category]["overdue_amount"] += outstanding
                    summary[category]["overdue_count"] += 1

                    # Calculate interest
                    interest = calculate_debt_interest(
                        outstanding, debt.get("interest_rate", 0), days_overdue
                    )
                    summary[category]["accrued_interest"] += interest

                    # Aging buckets
                    if days_overdue <= 30:
                        summary["aging"]["days_1_30"] += outstanding
                    elif days_overdue <= 60:
                        summary["aging"]["days_31_60"] += outstanding
                    elif days_overdue <= 90:
                        summary["aging"]["days_61_90"] += outstanding
                    else:
                        summary["aging"]["days_over_90"] += outstanding
                else:
                    summary["aging"]["current"] += outstanding
            except:
                summary["aging"]["current"] += outstanding

    # Net position
    summary["net_position"] = (
        summary["receivables"]["outstanding"] - summary["payables"]["outstanding"]
    )

    return summary


# ============== COMPREHENSIVE REPORTS ==============


@api_router.get("/reports/transactions-detailed")
async def get_transactions_detailed_report(
    user: dict = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    transaction_type: Optional[str] = None,
    currency: Optional[str] = None,
):
    """Detailed transaction report with base currency breakdown"""
    query = {"status": {"$in": ["approved", "completed"]}}

    if start_date:
        query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in query:
            query["created_at"]["$lte"] = end_date
        else:
            query["created_at"] = {"$lte": end_date}
    if transaction_type:
        query["transaction_type"] = transaction_type
    if currency:
        query["$or"] = [{"currency": currency}, {"base_currency": currency}]

    # Aggregation for summary by currency
    currency_pipeline = [
        {"$match": query},
        {
            "$group": {
                "_id": {
                    "type": "$transaction_type",
                    "currency": {"$ifNull": ["$base_currency", "$currency"]},
                },
                "total_base_amount": {"$sum": {"$ifNull": ["$base_amount", "$amount"]}},
                "total_usd_amount": {"$sum": "$amount"},
                "count": {"$sum": 1},
            }
        },
    ]

    currency_summary = await db.transactions.aggregate(currency_pipeline).to_list(100)

    # Build response
    deposits_by_currency = []
    withdrawals_by_currency = []
    total_deposits_usd = 0
    total_withdrawals_usd = 0
    deposit_count = 0
    withdrawal_count = 0

    for item in currency_summary:
        entry = {
            "currency": item["_id"]["currency"] or "USD",
            "amount": item["total_base_amount"],
            "usd_equivalent": item["total_usd_amount"],
            "count": item["count"],
        }
        if item["_id"]["type"] == "deposit":
            deposits_by_currency.append(entry)
            total_deposits_usd += item["total_usd_amount"]
            deposit_count += item["count"]
        elif item["_id"]["type"] == "withdrawal":
            withdrawals_by_currency.append(entry)
            total_withdrawals_usd += item["total_usd_amount"]
            withdrawal_count += item["count"]

    # Get recent transactions for the table
    transactions = (
        await db.transactions.find(query, {"_id": 0})
        .sort("created_at", -1)
        .limit(500)
        .to_list(500)
    )

    return {
        "summary": {
            "total_deposits_usd": total_deposits_usd,
            "total_withdrawals_usd": total_withdrawals_usd,
            "net_flow_usd": total_deposits_usd - total_withdrawals_usd,
            "deposit_count": deposit_count,
            "withdrawal_count": withdrawal_count,
            "total_count": deposit_count + withdrawal_count,
        },
        "deposits_by_currency": deposits_by_currency,
        "withdrawals_by_currency": withdrawals_by_currency,
        "transactions": transactions,
    }


@api_router.get("/reports/vendor-summary")
async def get_vendor_summary_report(
    user: dict = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    vendor_id: Optional[str] = None,
):
    """Vendor settlement and commission report with base currency"""
    query = {
        "vendor_id": {"$exists": True, "$ne": None},
        "status": {"$in": ["approved", "completed"]},
    }

    if start_date:
        query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in query:
            query["created_at"]["$lte"] = end_date
        else:
            query["created_at"] = {"$lte": end_date}
    if vendor_id:
        query["vendor_id"] = vendor_id

    # Get all vendors
    vendors = await db.vendors.find({}, {"_id": 0}).to_list(1000)
    vendor_map = {v["vendor_id"]: v for v in vendors}

    # Aggregation by vendor and currency
    pipeline = [
        {"$match": query},
        {
            "$group": {
                "_id": {
                    "vendor_id": "$vendor_id",
                    "type": "$transaction_type",
                    "currency": {"$ifNull": ["$base_currency", "$currency"]},
                },
                "total_base_amount": {"$sum": {"$ifNull": ["$base_amount", "$amount"]}},
                "total_usd_amount": {"$sum": "$amount"},
                "total_commission_base": {
                    "$sum": {"$ifNull": ["$vendor_commission_base_amount", 0]}
                },
                "total_commission_usd": {
                    "$sum": {"$ifNull": ["$vendor_commission_amount", 0]}
                },
                "count": {"$sum": 1},
            }
        },
    ]

    results = await db.transactions.aggregate(pipeline).to_list(1000)

    # Organize by vendor
    vendor_reports = {}
    for r in results:
        vid = r["_id"]["vendor_id"]
        if vid not in vendor_reports:
            vendor_info = vendor_map.get(vid, {})
            vendor_reports[vid] = {
                "vendor_id": vid,
                "vendor_name": vendor_info.get("vendor_name", "Unknown"),
                "deposit_commission_rate": vendor_info.get("deposit_commission", 0),
                "withdrawal_commission_rate": vendor_info.get(
                    "withdrawal_commission", 0
                ),
                "currencies": {},
                "totals": {
                    "deposits_usd": 0,
                    "withdrawals_usd": 0,
                    "commission_usd": 0,
                    "net_settlement_usd": 0,
                    "deposit_count": 0,
                    "withdrawal_count": 0,
                },
            }

        currency = r["_id"]["currency"] or "USD"
        tx_type = r["_id"]["type"]

        if currency not in vendor_reports[vid]["currencies"]:
            vendor_reports[vid]["currencies"][currency] = {
                "deposits_base": 0,
                "withdrawals_base": 0,
                "commission_base": 0,
                "net_settlement_base": 0,
                "deposits_usd": 0,
                "withdrawals_usd": 0,
                "commission_usd": 0,
                "net_settlement_usd": 0,
            }

        curr_data = vendor_reports[vid]["currencies"][currency]

        if tx_type == "deposit":
            curr_data["deposits_base"] += r["total_base_amount"]
            curr_data["deposits_usd"] += r["total_usd_amount"]
            vendor_reports[vid]["totals"]["deposits_usd"] += r["total_usd_amount"]
            vendor_reports[vid]["totals"]["deposit_count"] += r["count"]
        elif tx_type == "withdrawal":
            curr_data["withdrawals_base"] += r["total_base_amount"]
            curr_data["withdrawals_usd"] += r["total_usd_amount"]
            vendor_reports[vid]["totals"]["withdrawals_usd"] += r["total_usd_amount"]
            vendor_reports[vid]["totals"]["withdrawal_count"] += r["count"]

        curr_data["commission_base"] += r["total_commission_base"]
        curr_data["commission_usd"] += r["total_commission_usd"]
        vendor_reports[vid]["totals"]["commission_usd"] += r["total_commission_usd"]

    # Calculate net settlements
    for vid, data in vendor_reports.items():
        for currency, curr_data in data["currencies"].items():
            curr_data["net_settlement_base"] = (
                curr_data["deposits_base"] - curr_data["withdrawals_base"]
            ) - curr_data["commission_base"]
            curr_data["net_settlement_usd"] = (
                curr_data["deposits_usd"] - curr_data["withdrawals_usd"]
            ) - curr_data["commission_usd"]
        data["totals"]["net_settlement_usd"] = (
            data["totals"]["deposits_usd"] - data["totals"]["withdrawals_usd"]
        ) - data["totals"]["commission_usd"]

    # Grand totals
    grand_totals = {
        "total_deposits_usd": sum(
            v["totals"]["deposits_usd"] for v in vendor_reports.values()
        ),
        "total_withdrawals_usd": sum(
            v["totals"]["withdrawals_usd"] for v in vendor_reports.values()
        ),
        "total_commission_usd": sum(
            v["totals"]["commission_usd"] for v in vendor_reports.values()
        ),
        "total_net_settlement_usd": sum(
            v["totals"]["net_settlement_usd"] for v in vendor_reports.values()
        ),
        "total_vendors": len(vendor_reports),
    }

    return {"vendors": list(vendor_reports.values()), "grand_totals": grand_totals}


@api_router.get("/reports/vendor-commissions")
async def get_vendor_commissions_report(
    user: dict = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    """Detailed vendor commission report"""
    query = {
        "vendor_id": {"$exists": True, "$ne": None},
        "vendor_commission_amount": {"$gt": 0},
        "status": {"$in": ["approved", "completed"]},
    }

    if start_date:
        query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in query:
            query["created_at"]["$lte"] = end_date
        else:
            query["created_at"] = {"$lte": end_date}

    # Get all vendors
    vendors = await db.vendors.find({}, {"_id": 0}).to_list(1000)
    vendor_map = {v["vendor_id"]: v for v in vendors}

    # Get commission transactions
    transactions = (
        await db.transactions.find(query, {"_id": 0})
        .sort("created_at", -1)
        .to_list(1000)
    )

    # Aggregate by vendor
    vendor_commissions = {}
    for tx in transactions:
        vid = tx.get("vendor_id")
        if vid not in vendor_commissions:
            vendor_info = vendor_map.get(vid, {})
            vendor_commissions[vid] = {
                "vendor_id": vid,
                "vendor_name": vendor_info.get("vendor_name", "Unknown"),
                "total_commission_usd": 0,
                "commission_by_currency": {},
                "deposit_commissions": 0,
                "withdrawal_commissions": 0,
                "transaction_count": 0,
            }

        comm_usd = tx.get("vendor_commission_amount", 0)
        comm_base = tx.get("vendor_commission_base_amount", 0)
        currency = tx.get("base_currency") or tx.get("currency", "USD")

        vendor_commissions[vid]["total_commission_usd"] += comm_usd
        vendor_commissions[vid]["transaction_count"] += 1

        if tx.get("transaction_type") == "deposit":
            vendor_commissions[vid]["deposit_commissions"] += comm_usd
        else:
            vendor_commissions[vid]["withdrawal_commissions"] += comm_usd

        if currency not in vendor_commissions[vid]["commission_by_currency"]:
            vendor_commissions[vid]["commission_by_currency"][currency] = {
                "base": 0,
                "usd": 0,
            }
        vendor_commissions[vid]["commission_by_currency"][currency]["base"] += comm_base
        vendor_commissions[vid]["commission_by_currency"][currency]["usd"] += comm_usd

    return {
        "vendors": list(vendor_commissions.values()),
        "total_commission_usd": sum(
            v["total_commission_usd"] for v in vendor_commissions.values()
        ),
        "transactions": transactions[:100],  # Return last 100 commission transactions
    }


@api_router.get("/reports/client-balances")
async def get_client_balances_report(
    user: dict = Depends(get_current_user),
    min_balance: Optional[float] = None,
    max_balance: Optional[float] = None,
    sort_by: str = "net_balance",
    sort_order: str = "desc",
):
    """Client balance summary report"""
    clients = await db.clients.find({}, {"_id": 0}).to_list(10000)

    # Get transaction summaries for all clients
    pipeline = [
        {"$match": {"status": {"$in": ["approved", "completed"]}}},
        {
            "$group": {
                "_id": {
                    "client_id": "$client_id",
                    "type": "$transaction_type",
                    "currency": {"$ifNull": ["$base_currency", "$currency"]},
                },
                "total_base": {"$sum": {"$ifNull": ["$base_amount", "$amount"]}},
                "total_usd": {"$sum": "$amount"},
                "count": {"$sum": 1},
            }
        },
    ]

    tx_data = await db.transactions.aggregate(pipeline).to_list(100000)

    # Build client map
    client_tx_map = {}
    for item in tx_data:
        cid = item["_id"]["client_id"]
        if cid not in client_tx_map:
            client_tx_map[cid] = {
                "deposits_usd": 0,
                "withdrawals_usd": 0,
                "deposit_count": 0,
                "withdrawal_count": 0,
                "by_currency": {},
            }

        tx_type = item["_id"]["type"]
        currency = item["_id"]["currency"] or "USD"

        if currency not in client_tx_map[cid]["by_currency"]:
            client_tx_map[cid]["by_currency"][currency] = {
                "deposits": 0,
                "withdrawals": 0,
            }

        if tx_type == "deposit":
            client_tx_map[cid]["deposits_usd"] += item["total_usd"]
            client_tx_map[cid]["deposit_count"] += item["count"]
            client_tx_map[cid]["by_currency"][currency]["deposits"] += item[
                "total_base"
            ]
        elif tx_type == "withdrawal":
            client_tx_map[cid]["withdrawals_usd"] += item["total_usd"]
            client_tx_map[cid]["withdrawal_count"] += item["count"]
            client_tx_map[cid]["by_currency"][currency]["withdrawals"] += item[
                "total_base"
            ]

    # Enrich clients with transaction data
    results = []
    for client in clients:
        cid = client["client_id"]
        tx_info = client_tx_map.get(
            cid,
            {
                "deposits_usd": 0,
                "withdrawals_usd": 0,
                "deposit_count": 0,
                "withdrawal_count": 0,
                "by_currency": {},
            },
        )

        net_balance = tx_info["deposits_usd"] - tx_info["withdrawals_usd"]

        # Apply filters
        if min_balance is not None and net_balance < min_balance:
            continue
        if max_balance is not None and net_balance > max_balance:
            continue

        results.append(
            {
                "client_id": cid,
                "name": f"{client.get('first_name', '')} {client.get('last_name', '')}".strip(),
                "email": client.get("email"),
                "country": client.get("country"),
                "kyc_status": client.get("kyc_status"),
                "total_deposits_usd": tx_info["deposits_usd"],
                "total_withdrawals_usd": tx_info["withdrawals_usd"],
                "net_balance": net_balance,
                "deposit_count": tx_info["deposit_count"],
                "withdrawal_count": tx_info["withdrawal_count"],
                "transaction_count": tx_info["deposit_count"]
                + tx_info["withdrawal_count"],
                "by_currency": tx_info["by_currency"],
            }
        )

    # Sort
    reverse = sort_order == "desc"
    results.sort(key=lambda x: x.get(sort_by, 0) or 0, reverse=reverse)

    # Summary stats
    total_deposits = sum(r["total_deposits_usd"] for r in results)
    total_withdrawals = sum(r["total_withdrawals_usd"] for r in results)

    return {
        "clients": results,
        "summary": {
            "total_clients": len(results),
            "total_deposits_usd": total_deposits,
            "total_withdrawals_usd": total_withdrawals,
            "total_net_balance": total_deposits - total_withdrawals,
            "active_clients": len([r for r in results if r["transaction_count"] > 0]),
        },
    }


@api_router.get("/reports/treasury-summary")
async def get_treasury_summary_report(
    user: dict = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    """Treasury balances and transaction summary"""
    # Get all treasury accounts
    accounts = await db.treasury_accounts.find({}, {"_id": 0}).to_list(1000)

    # Calculate USD equivalents
    total_balance_usd = 0
    accounts_summary = []

    for acc in accounts:
        balance = acc.get("balance", 0)
        currency = acc.get("currency", "USD")
        balance_usd = convert_to_usd(balance, currency)
        total_balance_usd += balance_usd

        accounts_summary.append(
            {
                "account_id": acc["account_id"],
                "account_name": acc.get("account_name"),
                "account_type": acc.get("account_type"),
                "bank_name": acc.get("bank_name"),
                "currency": currency,
                "balance": balance,
                "balance_usd": balance_usd,
                "status": acc.get("status"),
            }
        )

    # Group by currency
    balance_by_currency = {}
    for acc in accounts:
        currency = acc.get("currency", "USD")
        if currency not in balance_by_currency:
            balance_by_currency[currency] = {"total": 0, "count": 0}
        balance_by_currency[currency]["total"] += acc.get("balance", 0)
        balance_by_currency[currency]["count"] += 1

    # Get transfer history
    query = {}
    if start_date:
        query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in query:
            query["created_at"]["$lte"] = end_date
        else:
            query["created_at"] = {"$lte": end_date}

    transfers = (
        await db.treasury_transactions.find(
            {**query, "transaction_type": {"$in": ["transfer_in", "transfer_out"]}},
            {"_id": 0},
        )
        .sort("created_at", -1)
        .limit(100)
        .to_list(100)
    )

    return {
        "accounts": accounts_summary,
        "total_balance_usd": total_balance_usd,
        "balance_by_currency": [
            {"currency": k, "total": v["total"], "account_count": v["count"]}
            for k, v in balance_by_currency.items()
        ],
        "recent_transfers": transfers,
    }


@api_router.get("/reports/psp-summary")
async def get_psp_summary_report(
    user: dict = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    """PSP transaction and settlement summary"""
    # Get all PSPs
    psps = await db.psps.find({}, {"_id": 0}).to_list(1000)

    # Build query for transactions
    query = {"destination_type": "psp"}
    if start_date:
        query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in query:
            query["created_at"]["$lte"] = end_date
        else:
            query["created_at"] = {"$lte": end_date}

    # Aggregate by PSP
    pipeline = [
        {"$match": query},
        {
            "$group": {
                "_id": "$psp_id",
                "total_volume": {"$sum": "$amount"},
                "total_commission": {
                    "$sum": {"$ifNull": ["$psp_commission_amount", 0]}
                },
                "total_net": {"$sum": {"$ifNull": ["$psp_net_amount", "$amount"]}},
                "settled_count": {
                    "$sum": {"$cond": [{"$eq": ["$settled", True]}, 1, 0]}
                },
                "pending_count": {
                    "$sum": {"$cond": [{"$ne": ["$settled", True]}, 1, 0]}
                },
                "transaction_count": {"$sum": 1},
            }
        },
    ]

    psp_stats = await db.transactions.aggregate(pipeline).to_list(100)
    psp_map = {p["psp_id"]: p for p in psps}

    results = []
    for stat in psp_stats:
        psp_id = stat["_id"]
        psp_info = psp_map.get(psp_id, {})

        results.append(
            {
                "psp_id": psp_id,
                "psp_name": psp_info.get("psp_name", "Unknown"),
                "commission_rate": psp_info.get("commission_rate", 0),
                "total_volume": stat["total_volume"],
                "total_commission": stat["total_commission"],
                "total_net": stat["total_net"],
                "settled_count": stat["settled_count"],
                "pending_count": stat["pending_count"],
                "transaction_count": stat["transaction_count"],
            }
        )

    return {
        "psps": results,
        "grand_totals": {
            "total_volume": sum(r["total_volume"] for r in results),
            "total_commission": sum(r["total_commission"] for r in results),
            "total_net": sum(r["total_net"] for r in results),
            "total_transactions": sum(r["transaction_count"] for r in results),
        },
    }


@api_router.get("/reports/financial-summary")
async def get_financial_summary_report(
    user: dict = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    """P&L and financial summary combining all data sources"""
    query = {}
    if start_date:
        query["date"] = {"$gte": start_date}
    if end_date:
        if "date" in query:
            query["date"]["$lte"] = end_date
        else:
            query["date"] = {"$lte": end_date}

    # Get income/expense summary
    ie_pipeline = [
        {"$match": query} if query else {"$match": {}},
        {
            "$group": {
                "_id": {"type": "$entry_type", "category": "$category"},
                "total": {"$sum": "$amount"},
                "count": {"$sum": 1},
            }
        },
    ]

    ie_data = await db.income_expenses.aggregate(ie_pipeline).to_list(100)

    income_by_category = {}
    expense_by_category = {}
    total_income = 0
    total_expense = 0

    for item in ie_data:
        category = item["_id"]["category"]
        entry_type = item["_id"]["type"]

        if entry_type == "income":
            income_by_category[category] = item["total"]
            total_income += item["total"]
        else:
            expense_by_category[category] = item["total"]
            total_expense += item["total"]

    # Get loan summary
    loans = await db.loans.find({}, {"_id": 0}).to_list(1000)
    total_loan_disbursed = sum(l.get("amount", 0) for l in loans)
    total_loan_outstanding = sum(
        l.get("outstanding_balance", l.get("amount", 0)) for l in loans
    )
    total_loan_repaid = sum(l.get("total_repaid", 0) for l in loans)

    # Get treasury total
    accounts = await db.treasury_accounts.find(
        {"status": "active"}, {"_id": 0}
    ).to_list(1000)
    total_treasury_usd = sum(
        convert_to_usd(a.get("balance", 0), a.get("currency", "USD")) for a in accounts
    )

    # Get vendor commission totals
    vendor_comm_pipeline = [
        {"$match": {"vendor_commission_amount": {"$gt": 0}}},
        {"$group": {"_id": None, "total": {"$sum": "$vendor_commission_amount"}}},
    ]
    vendor_comm = await db.transactions.aggregate(vendor_comm_pipeline).to_list(1)
    total_vendor_commission = vendor_comm[0]["total"] if vendor_comm else 0

    return {
        "income": {
            "total": total_income,
            "by_category": [
                {"category": k, "amount": v} for k, v in income_by_category.items()
            ],
        },
        "expenses": {
            "total": total_expense,
            "by_category": [
                {"category": k, "amount": v} for k, v in expense_by_category.items()
            ],
        },
        "net_profit_loss": total_income - total_expense,
        "loans": {
            "total_disbursed": total_loan_disbursed,
            "total_outstanding": total_loan_outstanding,
            "total_repaid": total_loan_repaid,
            "active_loans": len([l for l in loans if l.get("status") != "fully_paid"]),
        },
        "treasury": {
            "total_balance_usd": total_treasury_usd,
            "account_count": len(accounts),
        },
        "vendor_commissions": {"total_paid": total_vendor_commission},
    }


# ============== RECONCILIATION MODULE ==============

import csv
import io
from openpyxl import load_workbook


class ReconciliationStatus(str, Enum):
    PENDING = "pending"
    MATCHED = "matched"
    PARTIAL = "partial"
    UNMATCHED = "unmatched"
    DISCREPANCY = "discrepancy"


class ReconciliationType(str, Enum):
    BANK = "bank"
    PSP = "psp"
    CLIENT = "client"
    VENDOR = "vendor"


# Bank Statement Upload and Reconciliation
@api_router.post("/reconciliation/bank/upload")
async def upload_bank_statement(
    account_id: str = Form(...),
    file: UploadFile = File(...),
    user: dict = Depends(require_admin),
):
    """Upload bank statement CSV/Excel for reconciliation"""

    # Verify treasury account exists
    account = await db.treasury_accounts.find_one(
        {"account_id": account_id}, {"_id": 0}
    )
    if not account:
        raise HTTPException(status_code=404, detail="Treasury account not found")

    # Read file content
    content = await file.read()
    filename = file.filename.lower()

    parsed_rows = []

    try:
        if filename.endswith(".csv"):
            # Parse CSV
            decoded = content.decode("utf-8")
            reader = csv.DictReader(io.StringIO(decoded))
            for row in reader:
                parsed_rows.append(dict(row))
        elif filename.endswith((".xlsx", ".xls")):
            # Parse Excel
            wb = load_workbook(filename=io.BytesIO(content), read_only=True)
            ws = wb.active
            headers = [cell.value for cell in ws[1]]
            for row in ws.iter_rows(min_row=2, values_only=True):
                row_dict = {
                    headers[i]: row[i] for i in range(len(headers)) if i < len(row)
                }
                parsed_rows.append(row_dict)
        else:
            raise HTTPException(
                status_code=400, detail="Unsupported file format. Use CSV or Excel."
            )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse file: {str(e)}")

    if not parsed_rows:
        raise HTTPException(status_code=400, detail="No data found in file")

    now = datetime.now(timezone.utc)
    batch_id = f"recon_{uuid.uuid4().hex[:12]}"

    # Create reconciliation batch record
    batch_doc = {
        "batch_id": batch_id,
        "type": "bank",
        "account_id": account_id,
        "account_name": account["account_name"],
        "filename": file.filename,
        "total_rows": len(parsed_rows),
        "matched": 0,
        "unmatched": 0,
        "discrepancies": 0,
        "status": "processing",
        "created_at": now.isoformat(),
        "created_by": user["user_id"],
        "created_by_name": user["name"],
    }
    await db.reconciliation_batches.insert_one(batch_doc)

    # Process each row and try to match with treasury transactions
    matched_count = 0
    unmatched_count = 0
    discrepancy_count = 0

    for idx, row in enumerate(parsed_rows):
        # Try to extract amount, date, reference from common column names
        amount = None
        date = None
        reference = None
        description = None

        for key, value in row.items():
            key_lower = key.lower() if key else ""
            if any(
                x in key_lower for x in ["amount", "value", "debit", "credit", "sum"]
            ):
                try:
                    # Clean the amount string
                    clean_val = (
                        str(value).replace(",", "").replace("$", "").replace(" ", "")
                    )
                    amount = (
                        float(clean_val) if clean_val and clean_val != "None" else None
                    )
                except:
                    pass
            elif any(x in key_lower for x in ["date", "time", "posted"]):
                date = str(value) if value else None
            elif any(
                x in key_lower for x in ["reference", "ref", "txn", "transaction", "id"]
            ):
                reference = str(value) if value else None
            elif any(
                x in key_lower
                for x in ["description", "desc", "narration", "details", "memo"]
            ):
                description = str(value) if value else None

        # Create statement entry
        entry_id = f"stmt_{uuid.uuid4().hex[:12]}"
        entry_doc = {
            "entry_id": entry_id,
            "batch_id": batch_id,
            "account_id": account_id,
            "row_number": idx + 1,
            "raw_data": row,
            "parsed_amount": amount,
            "parsed_date": date,
            "parsed_reference": reference,
            "parsed_description": description,
            "status": ReconciliationStatus.PENDING,
            "matched_transaction_id": None,
            "variance": None,
            "created_at": now.isoformat(),
        }

        # Try to find matching treasury transaction
        if amount is not None:
            # Look for matching transaction by amount and optionally reference
            match_query = {
                "account_id": account_id,
                "amount": {
                    "$gte": abs(amount) - 0.01,
                    "$lte": abs(amount) + 0.01,
                },  # Allow small variance
            }
            if reference:
                match_query["$or"] = [
                    {"reference": {"$regex": reference, "$options": "i"}},
                    {"treasury_transaction_id": {"$regex": reference, "$options": "i"}},
                ]

            potential_match = await db.treasury_transactions.find_one(
                match_query, {"_id": 0}
            )

            if potential_match:
                # Calculate variance
                variance = abs(amount) - potential_match.get("amount", 0)

                if abs(variance) < 0.01:
                    entry_doc["status"] = ReconciliationStatus.MATCHED
                    entry_doc["matched_transaction_id"] = potential_match[
                        "treasury_transaction_id"
                    ]
                    matched_count += 1
                else:
                    entry_doc["status"] = ReconciliationStatus.DISCREPANCY
                    entry_doc["matched_transaction_id"] = potential_match[
                        "treasury_transaction_id"
                    ]
                    entry_doc["variance"] = variance
                    discrepancy_count += 1
            else:
                entry_doc["status"] = ReconciliationStatus.UNMATCHED
                unmatched_count += 1
        else:
            entry_doc["status"] = ReconciliationStatus.UNMATCHED
            unmatched_count += 1

        await db.reconciliation_entries.insert_one(entry_doc)

    # Update batch with results
    await db.reconciliation_batches.update_one(
        {"batch_id": batch_id},
        {
            "$set": {
                "matched": matched_count,
                "unmatched": unmatched_count,
                "discrepancies": discrepancy_count,
                "status": "completed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    )

    return {
        "batch_id": batch_id,
        "total_rows": len(parsed_rows),
        "matched": matched_count,
        "unmatched": unmatched_count,
        "discrepancies": discrepancy_count,
        "columns_detected": list(parsed_rows[0].keys()) if parsed_rows else [],
    }


@api_router.get("/reconciliation/batches")
async def get_reconciliation_batches(
    type: Optional[str] = None, limit: int = 50, user: dict = Depends(get_current_user)
):
    """Get reconciliation batch history"""
    query = {}
    if type:
        query["type"] = type

    batches = (
        await db.reconciliation_batches.find(query, {"_id": 0})
        .sort("created_at", -1)
        .to_list(limit)
    )
    return batches


@api_router.get("/reconciliation/batch/{batch_id}")
async def get_reconciliation_batch(
    batch_id: str, user: dict = Depends(get_current_user)
):
    """Get reconciliation batch details with entries"""
    batch = await db.reconciliation_batches.find_one({"batch_id": batch_id}, {"_id": 0})
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    entries = await db.reconciliation_entries.find(
        {"batch_id": batch_id}, {"_id": 0}
    ).to_list(10000)

    return {"batch": batch, "entries": entries}


@api_router.put("/reconciliation/entry/{entry_id}/match")
async def manually_match_entry(
    entry_id: str, transaction_id: str, user: dict = Depends(require_admin)
):
    """Manually match a reconciliation entry to a transaction"""
    entry = await db.reconciliation_entries.find_one({"entry_id": entry_id}, {"_id": 0})
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    # Verify transaction exists
    tx = await db.treasury_transactions.find_one(
        {"treasury_transaction_id": transaction_id}, {"_id": 0}
    )
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    variance = (entry.get("parsed_amount") or 0) - tx.get("amount", 0)

    await db.reconciliation_entries.update_one(
        {"entry_id": entry_id},
        {
            "$set": {
                "status": (
                    ReconciliationStatus.MATCHED
                    if abs(variance) < 0.01
                    else ReconciliationStatus.DISCREPANCY
                ),
                "matched_transaction_id": transaction_id,
                "variance": variance,
                "matched_by": user["user_id"],
                "matched_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    )

    # Update batch counts
    batch = await db.reconciliation_batches.find_one(
        {"batch_id": entry["batch_id"]}, {"_id": 0}
    )
    if batch:
        await db.reconciliation_batches.update_one(
            {"batch_id": entry["batch_id"]}, {"$inc": {"matched": 1, "unmatched": -1}}
        )

    return {"message": "Entry matched successfully"}


@api_router.put("/reconciliation/entry/{entry_id}/ignore")
async def ignore_reconciliation_entry(
    entry_id: str, reason: str = "", user: dict = Depends(require_admin)
):
    """Mark an entry as ignored/resolved"""
    await db.reconciliation_entries.update_one(
        {"entry_id": entry_id},
        {
            "$set": {
                "status": "ignored",
                "ignore_reason": reason,
                "ignored_by": user["user_id"],
                "ignored_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    return {"message": "Entry ignored"}


# PSP Reconciliation
@api_router.get("/reconciliation/psp")
async def get_psp_reconciliation(
    psp_id: Optional[str] = None, user: dict = Depends(get_current_user)
):
    """Get PSP reconciliation summary - expected vs actual settlements"""
    query = {"destination_type": "psp", "settled": True}
    if psp_id:
        query["psp_id"] = psp_id

    settled_txs = await db.transactions.find(query, {"_id": 0}).to_list(10000)

    # Group by PSP
    psp_summary = {}
    for tx in settled_txs:
        pid = tx.get("psp_id", "unknown")
        if pid not in psp_summary:
            psp_summary[pid] = {
                "psp_id": pid,
                "psp_name": tx.get("psp_name", "Unknown"),
                "total_transactions": 0,
                "expected_amount": 0,
                "actual_amount": 0,
                "total_variance": 0,
                "transactions_with_variance": 0,
            }

        psp_summary[pid]["total_transactions"] += 1
        expected = tx.get("psp_net_amount", tx.get("amount", 0))
        actual = tx.get("psp_actual_amount_received", expected)
        variance = tx.get("psp_settlement_variance", 0)

        psp_summary[pid]["expected_amount"] += expected
        psp_summary[pid]["actual_amount"] += actual
        psp_summary[pid]["total_variance"] += variance
        if abs(variance) > 0.01:
            psp_summary[pid]["transactions_with_variance"] += 1

    return list(psp_summary.values())


@api_router.get("/reconciliation/psp/{psp_id}/details")
async def get_psp_reconciliation_details(
    psp_id: str, user: dict = Depends(get_current_user)
):
    """Get detailed PSP reconciliation with individual transaction variances"""
    txs = (
        await db.transactions.find(
            {"destination_type": "psp", "psp_id": psp_id, "settled": True}, {"_id": 0}
        )
        .sort("settled_at", -1)
        .to_list(1000)
    )

    result = []
    for tx in txs:
        expected = tx.get("psp_net_amount", tx.get("amount", 0))
        actual = tx.get("psp_actual_amount_received", expected)
        variance = tx.get("psp_settlement_variance", actual - expected)

        result.append(
            {
                "transaction_id": tx.get("transaction_id"),
                "reference": tx.get("reference"),
                "client_name": tx.get("client_name"),
                "gross_amount": tx.get("amount"),
                "commission": tx.get("psp_commission_amount", 0),
                "chargeback": tx.get(
                    "psp_reserve_fund_amount", tx.get("psp_chargeback_amount", 0)
                ),
                "extra_charges": tx.get("psp_extra_charges", 0),
                "expected_net": expected,
                "actual_received": actual,
                "variance": variance,
                "settled_at": tx.get("settled_at"),
                "status": "matched" if abs(variance) < 0.01 else "variance",
            }
        )

    return result


# Client Account Reconciliation
@api_router.get("/reconciliation/clients")
async def get_client_reconciliation(user: dict = Depends(get_current_user)):
    """Get client account reconciliation - verify balances match transactions"""
    clients = await db.clients.find({}, {"_id": 0}).to_list(10000)

    result = []
    for client in clients:
        client_id = client.get("client_id")

        # Get all transactions for this client
        txs = await db.transactions.find(
            {"client_id": client_id, "status": {"$in": ["approved", "completed"]}},
            {"_id": 0},
        ).to_list(10000)

        # Calculate expected balance from transactions
        calculated_balance = 0
        for tx in txs:
            amount = tx.get("amount", 0)
            if tx.get("transaction_type") == "deposit":
                calculated_balance += amount
            elif tx.get("transaction_type") == "withdrawal":
                calculated_balance -= amount

        recorded_balance = client.get("balance", 0)
        variance = recorded_balance - calculated_balance

        result.append(
            {
                "client_id": client_id,
                "client_name": f"{client.get('first_name', '')} {client.get('last_name', '')}".strip(),
                "recorded_balance": recorded_balance,
                "calculated_balance": calculated_balance,
                "variance": variance,
                "transaction_count": len(txs),
                "status": "matched" if abs(variance) < 0.01 else "discrepancy",
            }
        )

    # Sort by variance (largest first)
    result.sort(key=lambda x: abs(x["variance"]), reverse=True)
    return result


@api_router.get("/reconciliation/client/{client_id}/details")
async def get_client_reconciliation_details(
    client_id: str, user: dict = Depends(get_current_user)
):
    """Get detailed transaction history for client reconciliation"""
    client = await db.clients.find_one({"client_id": client_id}, {"_id": 0})
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    txs = (
        await db.transactions.find(
            {"client_id": client_id, "status": {"$in": ["approved", "completed"]}},
            {"_id": 0},
        )
        .sort("created_at", 1)
        .to_list(10000)
    )

    # Build running balance history
    running_balance = 0
    history = []
    for tx in txs:
        amount = tx.get("amount", 0)
        if tx.get("transaction_type") == "deposit":
            running_balance += amount
        elif tx.get("transaction_type") == "withdrawal":
            running_balance -= amount

        history.append(
            {
                "transaction_id": tx.get("transaction_id"),
                "date": tx.get("created_at"),
                "type": tx.get("transaction_type"),
                "amount": amount,
                "running_balance": running_balance,
                "reference": tx.get("reference"),
            }
        )

    return {
        "client": {
            "client_id": client_id,
            "name": f"{client.get('first_name', '')} {client.get('last_name', '')}".strip(),
            "recorded_balance": client.get("balance", 0),
            "calculated_balance": running_balance,
            "variance": client.get("balance", 0) - running_balance,
        },
        "transactions": history,
    }


# Vendor Reconciliation
@api_router.get("/reconciliation/vendors")
async def get_vendor_reconciliation(user: dict = Depends(get_current_user)):
    """Get vendor reconciliation - commission calculations vs payments"""
    vendors = await db.vendors.find({}, {"_id": 0}).to_list(1000)

    result = []
    for vendor in vendors:
        vendor_id = vendor.get("vendor_id")

        # Get all transactions through this vendor
        txs = await db.transactions.find(
            {"vendor_id": vendor_id, "status": {"$in": ["approved", "completed"]}},
            {"_id": 0},
        ).to_list(10000)

        # Calculate expected commission
        total_volume = sum(tx.get("amount", 0) for tx in txs)
        commission_rate = vendor.get("commission_rate", 0) / 100
        expected_commission = total_volume * commission_rate

        # Get recorded commission
        paid_commission = vendor.get("total_commission_paid", 0)
        pending_commission = vendor.get("pending_commission", 0)
        total_recorded = paid_commission + pending_commission

        variance = expected_commission - total_recorded

        result.append(
            {
                "vendor_id": vendor_id,
                "vendor_name": vendor.get("name", "Unknown"),
                "commission_rate": vendor.get("commission_rate", 0),
                "total_volume": total_volume,
                "transaction_count": len(txs),
                "expected_commission": expected_commission,
                "paid_commission": paid_commission,
                "pending_commission": pending_commission,
                "total_recorded": total_recorded,
                "variance": variance,
                "status": "matched" if abs(variance) < 0.01 else "discrepancy",
            }
        )

    result.sort(key=lambda x: abs(x["variance"]), reverse=True)
    return result


# Reconciliation Dashboard Summary
@api_router.get("/reconciliation/summary")
async def get_reconciliation_summary(user: dict = Depends(get_current_user)):
    """Get overall reconciliation status summary"""

    # Bank reconciliation status
    bank_batches = (
        await db.reconciliation_batches.find({"type": "bank"}, {"_id": 0})
        .sort("created_at", -1)
        .to_list(10)
    )
    total_unmatched_bank = sum(b.get("unmatched", 0) for b in bank_batches)
    total_discrepancies_bank = sum(b.get("discrepancies", 0) for b in bank_batches)

    # PSP reconciliation
    psp_recon = await get_psp_reconciliation(None, user)
    total_psp_variance = sum(p.get("total_variance", 0) for p in psp_recon)
    psp_with_variance = sum(
        1 for p in psp_recon if abs(p.get("total_variance", 0)) > 0.01
    )

    # Client reconciliation
    client_recon = await get_client_reconciliation(user)
    clients_with_discrepancy = sum(
        1 for c in client_recon if c["status"] == "discrepancy"
    )
    total_client_variance = sum(abs(c["variance"]) for c in client_recon)

    # Vendor reconciliation
    vendor_recon = await get_vendor_reconciliation(user)
    vendors_with_discrepancy = sum(
        1 for v in vendor_recon if v["status"] == "discrepancy"
    )
    total_vendor_variance = sum(abs(v["variance"]) for v in vendor_recon)

    return {
        "bank": {
            "recent_batches": len(bank_batches),
            "unmatched_entries": total_unmatched_bank,
            "discrepancies": total_discrepancies_bank,
            "status": (
                "attention"
                if total_unmatched_bank > 0 or total_discrepancies_bank > 0
                else "ok"
            ),
        },
        "psp": {
            "total_psps": len(psp_recon),
            "psps_with_variance": psp_with_variance,
            "total_variance": total_psp_variance,
            "status": "attention" if psp_with_variance > 0 else "ok",
        },
        "clients": {
            "total_clients": len(client_recon),
            "clients_with_discrepancy": clients_with_discrepancy,
            "total_variance": total_client_variance,
            "status": "attention" if clients_with_discrepancy > 0 else "ok",
        },
        "vendors": {
            "total_vendors": len(vendor_recon),
            "vendors_with_discrepancy": vendors_with_discrepancy,
            "total_variance": total_vendor_variance,
            "status": "attention" if vendors_with_discrepancy > 0 else "ok",
        },
    }


# ============== EMAIL SETTINGS & DAILY REPORTS ==============


class EmailSettingsUpdate(BaseModel):
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_email: Optional[str] = None  # username for auth
    smtp_password: Optional[str] = None
    smtp_from_email: Optional[str] = None  # email to send from
    director_emails: Optional[List[str]] = None
    report_enabled: Optional[bool] = None
    report_time: Optional[str] = None  # Format: "HH:MM"


@api_router.get("/settings/email")
async def get_email_settings(user: dict = Depends(require_admin)):
    """Get email/report settings (password masked)"""
    settings = await db.app_settings.find_one({"setting_type": "email"}, {"_id": 0})
    if not settings:
        return {
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_email": "",
            "smtp_from_email": "",
            "smtp_password_set": False,
            "director_emails": [],
            "report_enabled": False,
            "report_time": "03:00",
        }
    return {
        "smtp_host": settings.get("smtp_host", "smtp.gmail.com"),
        "smtp_port": settings.get("smtp_port", 587),
        "smtp_email": settings.get("smtp_email", ""),
        "smtp_from_email": settings.get(
            "smtp_from_email", settings.get("smtp_email", "")
        ),
        "smtp_password_set": bool(settings.get("smtp_password")),
        "director_emails": settings.get("director_emails", []),
        "report_enabled": settings.get("report_enabled", False),
        "report_time": settings.get("report_time", "03:00"),
    }


@api_router.put("/settings/email")
async def update_email_settings(
    settings: EmailSettingsUpdate, user: dict = Depends(require_admin)
):
    """Update email/report settings"""
    now = datetime.now(timezone.utc)

    existing = await db.app_settings.find_one({"setting_type": "email"}, {"_id": 0})

    updates = {"updated_at": now.isoformat(), "updated_by": user["user_id"]}

    if settings.smtp_host is not None:
        updates["smtp_host"] = settings.smtp_host
    if settings.smtp_port is not None:
        updates["smtp_port"] = settings.smtp_port
    if settings.smtp_email is not None:
        updates["smtp_email"] = settings.smtp_email
    if settings.smtp_from_email is not None:
        updates["smtp_from_email"] = settings.smtp_from_email
    if settings.smtp_password is not None and settings.smtp_password != "":
        updates["smtp_password"] = settings.smtp_password  # In production, encrypt this
    if settings.director_emails is not None:
        updates["director_emails"] = settings.director_emails
    if settings.report_enabled is not None:
        updates["report_enabled"] = settings.report_enabled
    if settings.report_time is not None:
        updates["report_time"] = settings.report_time

    if existing:
        await db.app_settings.update_one({"setting_type": "email"}, {"$set": updates})
    else:
        updates["setting_type"] = "email"
        updates["created_at"] = now.isoformat()
        await db.app_settings.insert_one(updates)

    # Reschedule the daily report if time changed
    if settings.report_time or settings.report_enabled is not None:
        await reschedule_daily_report()

    return {"message": "Email settings updated successfully"}


@api_router.post("/settings/email/test")
async def test_email_settings(user: dict = Depends(require_admin)):
    """Send a test email to verify SMTP settings"""
    settings = await db.app_settings.find_one({"setting_type": "email"}, {"_id": 0})

    if (
        not settings
        or not settings.get("smtp_email")
        or not settings.get("smtp_password")
    ):
        raise HTTPException(status_code=400, detail="SMTP settings not configured")

    if not settings.get("director_emails"):
        raise HTTPException(status_code=400, detail="No director emails configured")

    try:
        await send_email(
            to_emails=settings["director_emails"],
            subject="Miles Capitals - Test Email",
            html_content=f"""
            <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0B0C10; color: white;">
                <h2 style="color: #66FCF1;">Test Email Successful!</h2>
                <p>This is a test email from Miles Capitals Back Office.</p>
                <p>If you received this, your email settings are configured correctly.</p>
                <p style="color: #C5C6C7; font-size: 12px;">Sent at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
            """,
            smtp_host=settings.get("smtp_host", "smtp.gmail.com"),
            smtp_port=settings.get("smtp_port", 587),
            smtp_email=settings["smtp_email"],
            smtp_password=settings["smtp_password"],
            smtp_from_email=settings.get("smtp_from_email", settings["smtp_email"]),
        )
        return {"message": "Test email sent successfully"}
    except Exception as e:
        logger.error(f"Test email failed: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to send test email: {str(e)}"
        )


async def send_email(
    to_emails: List[str],
    subject: str,
    html_content: str,
    smtp_host: str,
    smtp_port: int,
    smtp_email: str,
    smtp_password: str,
    smtp_from_email: str = None,
):
    """Send email via SMTP"""
    from_email = smtp_from_email or smtp_email

    message = MIMEMultipart("alternative")
    message["From"] = from_email
    message["To"] = ", ".join(to_emails)
    message["Subject"] = subject

    html_part = MIMEText(html_content, "html")
    message.attach(html_part)

    # Determine TLS settings based on port
    use_tls = smtp_port in [587, 25]  # STARTTLS ports
    use_ssl = smtp_port == 465  # Direct SSL port

    if use_ssl:
        await aiosmtplib.send(
            message,
            hostname=smtp_host,
            port=smtp_port,
            use_tls=True,
            username=smtp_email,
            password=smtp_password,
        )
    else:
        await aiosmtplib.send(
            message,
            hostname=smtp_host,
            port=smtp_port,
            start_tls=use_tls,
            username=smtp_email,
            password=smtp_password,
        )


async def generate_daily_report_html():
    """Generate comprehensive daily report HTML"""
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)

    # Fetch data for report
    # Today's transactions
    today_txs = await db.transactions.find(
        {"created_at": {"$gte": today_start.isoformat()}}, {"_id": 0}
    ).to_list(10000)

    today_deposits = sum(
        t.get("amount", 0) for t in today_txs if t.get("transaction_type") == "deposit"
    )
    today_withdrawals = sum(
        t.get("amount", 0)
        for t in today_txs
        if t.get("transaction_type") == "withdrawal"
    )

    # Treasury balances
    treasury_accounts = await db.treasury_accounts.find({}, {"_id": 0}).to_list(100)
    total_treasury = sum(
        convert_to_usd(a.get("balance", 0), a.get("currency", "USD"))
        for a in treasury_accounts
    )

    # PSP pending
    psps = await db.psps.find({"status": "active"}, {"_id": 0}).to_list(100)
    total_psp_pending = sum(p.get("pending_settlement", 0) for p in psps)

    # Pending PSP transactions
    psp_pending_txs = await db.transactions.find(
        {"destination_type": "psp", "settled": {"$ne": True}}, {"_id": 0}
    ).to_list(1000)

    # Outstanding accounts
    debts = await db.debts.find({"status": {"$ne": "fully_paid"}}, {"_id": 0}).to_list(
        1000
    )
    total_receivables = sum(
        d.get("amount", 0) - d.get("paid_amount", 0)
        for d in debts
        if d.get("debt_type") == "receivable"
    )
    total_payables = sum(
        d.get("amount", 0) - d.get("paid_amount", 0)
        for d in debts
        if d.get("debt_type") == "payable"
    )

    # Vendor pending
    vendors = await db.vendors.find({"status": "active"}, {"_id": 0}).to_list(100)

    # Pending approvals
    pending_txs = await db.transactions.find({"status": "pending"}, {"_id": 0}).to_list(
        1000
    )

    # Generate HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }}
            .container {{ max-width: 700px; margin: 0 auto; background-color: #0B0C10; color: white; }}
            .header {{ background: linear-gradient(135deg, #1F2833 0%, #0B0C10 100%); padding: 30px; text-align: center; border-bottom: 3px solid #66FCF1; }}
            .header h1 {{ color: #66FCF1; margin: 0; font-size: 28px; letter-spacing: 2px; }}
            .header p {{ color: #C5C6C7; margin: 10px 0 0; font-size: 14px; }}
            .content {{ padding: 30px; }}
            .section {{ background-color: #1F2833; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
            .section-title {{ color: #66FCF1; font-size: 16px; font-weight: bold; margin-bottom: 15px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid #66FCF1; padding-bottom: 10px; }}
            .stat-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }}
            .stat-box {{ background-color: #0B0C10; border-radius: 6px; padding: 15px; }}
            .stat-label {{ color: #C5C6C7; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
            .stat-value {{ color: white; font-size: 24px; font-weight: bold; margin-top: 5px; }}
            .stat-value.green {{ color: #4ade80; }}
            .stat-value.red {{ color: #f87171; }}
            .stat-value.cyan {{ color: #66FCF1; }}
            .stat-value.yellow {{ color: #fbbf24; }}
            .alert {{ background-color: #7f1d1d; border-left: 4px solid #ef4444; padding: 15px; margin-bottom: 20px; border-radius: 0 8px 8px 0; }}
            .alert-title {{ color: #fca5a5; font-weight: bold; margin-bottom: 5px; }}
            .alert-text {{ color: #fecaca; font-size: 14px; }}
            .footer {{ background-color: #1F2833; padding: 20px; text-align: center; border-top: 1px solid #333; }}
            .footer p {{ color: #C5C6C7; font-size: 12px; margin: 0; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
            th {{ color: #66FCF1; font-size: 11px; text-transform: uppercase; }}
            td {{ color: white; font-size: 13px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>MILES CAPITALS</h1>
                <p>Daily Business Report - {now.strftime('%B %d, %Y')}</p>
            </div>
            
            <div class="content">
                <!-- Alerts Section -->
                {"" if len(pending_txs) == 0 else f'''
                <div class="alert">
                    <div class="alert-title">⚠️ Action Required</div>
                    <div class="alert-text">{len(pending_txs)} transactions pending approval</div>
                </div>
                '''}
                
                <!-- Today's Activity -->
                <div class="section">
                    <div class="section-title">📊 Today's Activity</div>
                    <div class="stat-grid">
                        <div class="stat-box">
                            <div class="stat-label">Deposits</div>
                            <div class="stat-value green">+${today_deposits:,.2f}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Withdrawals</div>
                            <div class="stat-value red">-${today_withdrawals:,.2f}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Net Flow</div>
                            <div class="stat-value {'green' if today_deposits - today_withdrawals >= 0 else 'red'}">${today_deposits - today_withdrawals:,.2f}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Transactions</div>
                            <div class="stat-value cyan">{len(today_txs)}</div>
                        </div>
                    </div>
                </div>
                
                <!-- Treasury Status -->
                <div class="section">
                    <div class="section-title">🏦 Treasury Status</div>
                    <div class="stat-grid">
                        <div class="stat-box">
                            <div class="stat-label">Total Balance (USD)</div>
                            <div class="stat-value cyan">${total_treasury:,.2f}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Active Accounts</div>
                            <div class="stat-value">{len(treasury_accounts)}</div>
                        </div>
                    </div>
                    <table>
                        <tr><th>Account</th><th>Currency</th><th>Balance</th><th>USD Value</th></tr>
                        {''.join(f"<tr><td>{a.get('account_name', 'N/A')}</td><td>{a.get('currency', 'USD')}</td><td>{a.get('balance', 0):,.2f}</td><td>${convert_to_usd(a.get('balance', 0), a.get('currency', 'USD')):,.2f}</td></tr>" for a in treasury_accounts[:5])}
                    </table>
                </div>
                
                <!-- PSP Status -->
                <div class="section">
                    <div class="section-title">💳 PSP Status</div>
                    <div class="stat-grid">
                        <div class="stat-box">
                            <div class="stat-label">Pending Settlements</div>
                            <div class="stat-value yellow">${total_psp_pending:,.2f}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Pending Transactions</div>
                            <div class="stat-value">{len(psp_pending_txs)}</div>
                        </div>
                    </div>
                </div>
                
                <!-- Outstanding Accounts -->
                <div class="section">
                    <div class="section-title">📋 Outstanding Accounts</div>
                    <div class="stat-grid">
                        <div class="stat-box">
                            <div class="stat-label">Receivables (Owed to us)</div>
                            <div class="stat-value green">${total_receivables:,.2f}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Payables (We owe)</div>
                            <div class="stat-value red">${total_payables:,.2f}</div>
                        </div>
                    </div>
                </div>
                
                <!-- Pending Actions -->
                <div class="section">
                    <div class="section-title">⏳ Pending Actions</div>
                    <div class="stat-grid">
                        <div class="stat-box">
                            <div class="stat-label">Pending Approvals</div>
                            <div class="stat-value yellow">{len(pending_txs)}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Active Vendors</div>
                            <div class="stat-value">{len(vendors)}</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>This is an automated report from Miles Capitals Back Office</p>
                <p>Generated at {now.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </div>
    </body>
    </html>
    """

    return html


async def send_daily_report():
    """Send daily report to all directors"""
    try:
        settings = await db.app_settings.find_one({"setting_type": "email"}, {"_id": 0})

        if not settings or not settings.get("report_enabled"):
            logger.info("Daily report is disabled or not configured")
            return

        if not settings.get("smtp_email") or not settings.get("smtp_password"):
            logger.warning("SMTP settings not configured - skipping daily report")
            return

        if not settings.get("director_emails"):
            logger.warning("No director emails configured - skipping daily report")
            return

        html_content = await generate_daily_report_html()

        await send_email(
            to_emails=settings["director_emails"],
            subject=f"Miles Capitals - Daily Report ({datetime.now(timezone.utc).strftime('%Y-%m-%d')})",
            html_content=html_content,
            smtp_host=settings.get("smtp_host", "smtp.gmail.com"),
            smtp_port=settings.get("smtp_port", 587),
            smtp_email=settings["smtp_email"],
            smtp_password=settings["smtp_password"],
            smtp_from_email=settings.get("smtp_from_email", settings["smtp_email"]),
        )

        # Log successful send
        await db.email_logs.insert_one(
            {
                "log_id": f"email_{uuid.uuid4().hex[:12]}",
                "type": "daily_report",
                "recipients": settings["director_emails"],
                "status": "sent",
                "sent_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        logger.info(
            f"Daily report sent to {len(settings['director_emails'])} directors"
        )

    except Exception as e:
        logger.error(f"Failed to send daily report: {e}")
        await db.email_logs.insert_one(
            {
                "log_id": f"email_{uuid.uuid4().hex[:12]}",
                "type": "daily_report",
                "status": "failed",
                "error": str(e),
                "attempted_at": datetime.now(timezone.utc).isoformat(),
            }
        )


@api_router.post("/reports/send-now")
async def send_report_now(user: dict = Depends(require_admin)):
    """Manually trigger daily report send"""
    settings = await db.app_settings.find_one({"setting_type": "email"}, {"_id": 0})

    if (
        not settings
        or not settings.get("smtp_email")
        or not settings.get("smtp_password")
    ):
        raise HTTPException(status_code=400, detail="SMTP settings not configured")

    if not settings.get("director_emails"):
        raise HTTPException(status_code=400, detail="No director emails configured")

    try:
        html_content = await generate_daily_report_html()

        await send_email(
            to_emails=settings["director_emails"],
            subject=f"Miles Capitals - Daily Report ({datetime.now(timezone.utc).strftime('%Y-%m-%d')})",
            html_content=html_content,
            smtp_host=settings.get("smtp_host", "smtp.gmail.com"),
            smtp_port=settings.get("smtp_port", 587),
            smtp_email=settings["smtp_email"],
            smtp_password=settings["smtp_password"],
            smtp_from_email=settings.get("smtp_from_email", settings["smtp_email"]),
        )

        return {
            "message": f"Report sent to {len(settings['director_emails'])} directors"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send report: {str(e)}")


@api_router.get("/reports/email-logs")
async def get_email_logs(limit: int = 20, user: dict = Depends(require_admin)):
    """Get email send history"""
    logs = await db.email_logs.find({}, {"_id": 0}).sort("sent_at", -1).to_list(limit)
    return logs


# Scheduler instance
scheduler = AsyncIOScheduler()


async def reschedule_daily_report():
    """Reschedule the daily report based on current settings"""
    global scheduler

    # Remove existing job if any
    try:
        scheduler.remove_job("daily_report")
    except:
        pass

    settings = await db.app_settings.find_one({"setting_type": "email"}, {"_id": 0})

    if not settings or not settings.get("report_enabled"):
        logger.info("Daily report scheduling skipped - disabled")
        return

    report_time = settings.get("report_time", "03:00")
    hour, minute = map(int, report_time.split(":"))

    scheduler.add_job(
        send_daily_report,
        CronTrigger(hour=hour, minute=minute),
        id="daily_report",
        replace_existing=True,
    )

    logger.info(f"Daily report scheduled for {report_time}")


# ============== AUDIT & COMPLIANCE MODULE ==============


class AuditSeverity:
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class AuditCategory:
    TRANSACTION_INTEGRITY = "transaction_integrity"
    FX_RATE_VERIFICATION = "fx_rate_verification"
    PSP_SETTLEMENT = "psp_settlement"
    ANOMALY_DETECTION = "anomaly_detection"
    TREASURY_BALANCE = "treasury_balance"


async def run_audit_checks() -> dict:
    """Run all audit checks and return findings."""
    now = datetime.now(timezone.utc)
    findings = []
    stats = {
        "total_checks": 0,
        "critical": 0,
        "warning": 0,
        "info": 0,
        "passed": 0,
    }

    # ---- 1. TRANSACTION INTEGRITY ----
    all_txs = await db.transactions.find({}, {"_id": 0}).to_list(50000)
    stats["total_checks"] += 1

    # 1a. Missing fields
    for tx in all_txs:
        issues = []
        if not tx.get("client_id"):
            issues.append("Missing client_id")
        if not tx.get("reference"):
            issues.append("Missing reference")
        if not tx.get("amount") or tx.get("amount", 0) <= 0:
            issues.append("Invalid or zero amount")
        if not tx.get("currency"):
            issues.append("Missing currency")
        if (
            tx.get("status") == "completed"
            and tx.get("transaction_type") == "deposit"
            and not tx.get("proof_image")
            and not tx.get("accountant_proof_image")
        ):
            issues.append("Completed deposit without proof")
        if issues:
            findings.append(
                {
                    "category": AuditCategory.TRANSACTION_INTEGRITY,
                    "severity": AuditSeverity.WARNING,
                    "title": f"Data issue: {tx.get('reference', tx['transaction_id'])}",
                    "description": "; ".join(issues),
                    "transaction_id": tx["transaction_id"],
                    "reference": tx.get("reference"),
                }
            )
            stats["warning"] += 1

    # 1b. Duplicate detection (same client, same amount, within 5 minutes)
    from collections import defaultdict

    client_txs = defaultdict(list)
    for tx in all_txs:
        key = f"{tx.get('client_id')}_{tx.get('amount')}_{tx.get('transaction_type')}"
        client_txs[key].append(tx)

    for key, txs in client_txs.items():
        if len(txs) < 2:
            continue
        txs_sorted = sorted(txs, key=lambda x: x.get("created_at", ""))
        for i in range(1, len(txs_sorted)):
            try:
                t1 = datetime.fromisoformat(txs_sorted[i - 1].get("created_at", ""))
                t2 = datetime.fromisoformat(txs_sorted[i].get("created_at", ""))
                if abs((t2 - t1).total_seconds()) < 300:  # 5 minutes
                    findings.append(
                        {
                            "category": AuditCategory.ANOMALY_DETECTION,
                            "severity": AuditSeverity.WARNING,
                            "title": f"Potential duplicate: {txs_sorted[i].get('reference', '')}",
                            "description": f"Same client ({txs_sorted[i].get('client_name', 'N/A')}), same amount ({txs_sorted[i].get('amount', 0)} {txs_sorted[i].get('currency', 'USD')}), within 5 minutes of {txs_sorted[i-1].get('reference', '')}",
                            "transaction_id": txs_sorted[i]["transaction_id"],
                            "reference": txs_sorted[i].get("reference"),
                            "related_transaction": txs_sorted[i - 1]["transaction_id"],
                        }
                    )
                    stats["warning"] += 1
            except (ValueError, TypeError):
                continue
    stats["total_checks"] += 1

    # ---- 2. FX RATE VERIFICATION ----
    rates = _fx_cache.get("rates") or FALLBACK_RATES_TO_USD

    for tx in all_txs:
        if tx.get("base_currency") and tx.get("base_amount") and tx.get("amount"):
            base_curr = tx["base_currency"]
            if base_curr != "USD" and base_curr in rates:
                expected_usd = round(tx["base_amount"] * rates.get(base_curr, 1.0), 2)
                actual_usd = tx["amount"]
                if actual_usd > 0:
                    deviation_pct = abs(expected_usd - actual_usd) / actual_usd * 100
                    if deviation_pct > 5:
                        findings.append(
                            {
                                "category": AuditCategory.FX_RATE_VERIFICATION,
                                "severity": (
                                    AuditSeverity.CRITICAL
                                    if deviation_pct > 10
                                    else AuditSeverity.WARNING
                                ),
                                "title": f"FX rate deviation: {tx.get('reference', tx['transaction_id'])}",
                                "description": f"Expected ~{expected_usd:,.2f} USD from {tx['base_amount']:,.2f} {base_curr}, got {actual_usd:,.2f} USD ({deviation_pct:.1f}% deviation)",
                                "transaction_id": tx["transaction_id"],
                                "reference": tx.get("reference"),
                                "deviation_percent": round(deviation_pct, 2),
                            }
                        )
                        if deviation_pct > 10:
                            stats["critical"] += 1
                        else:
                            stats["warning"] += 1
    stats["total_checks"] += 1

    # ---- 3. PSP SETTLEMENT AUDIT ----
    psp_txs = [tx for tx in all_txs if tx.get("destination_type") == "psp"]
    psps = {p["psp_id"]: p for p in await db.psps.find({}, {"_id": 0}).to_list(1000)}
    treasury_accounts = {
        a["account_id"]: a
        for a in await db.treasury_accounts.find({}, {"_id": 0}).to_list(100)
    }

    for tx in psp_txs:
        psp = psps.get(tx.get("psp_id"))
        if not psp:
            continue

        # 3a. Verify net amount math
        # Note: psp_net_amount is amount after commission only (reserve fund deducted at settlement)
        amount = tx.get("amount", 0)
        commission = tx.get("psp_commission_amount", 0)
        expected_net = amount - commission
        actual_net = tx.get("psp_net_amount", 0)

        if actual_net and abs(expected_net - actual_net) > 0.02:
            findings.append(
                {
                    "category": AuditCategory.PSP_SETTLEMENT,
                    "severity": AuditSeverity.CRITICAL,
                    "title": f"Net amount mismatch: {tx.get('reference', tx['transaction_id'])}",
                    "description": f"Expected net {expected_net:,.2f} (amount {amount:,.2f} - commission {commission:,.2f}), actual net {actual_net:,.2f}",
                    "transaction_id": tx["transaction_id"],
                    "reference": tx.get("reference"),
                }
            )
            stats["critical"] += 1

        # 3b. Check reserve fund rate matches PSP setting
        reserve_fund = tx.get("psp_reserve_fund_amount", 0) or 0
        if reserve_fund > 0 and amount > 0:
            expected_rate = psp.get("reserve_fund_rate", 0)
            actual_rate = round(reserve_fund / amount * 100, 2)
            if expected_rate > 0 and abs(actual_rate - expected_rate) > 0.5:
                findings.append(
                    {
                        "category": AuditCategory.PSP_SETTLEMENT,
                        "severity": AuditSeverity.WARNING,
                        "title": f"Reserve fund rate mismatch: {tx.get('reference', tx['transaction_id'])}",
                        "description": f"PSP rate is {expected_rate}%, but transaction shows {actual_rate}% ({reserve_fund:,.2f} of {amount:,.2f})",
                        "transaction_id": tx["transaction_id"],
                        "reference": tx.get("reference"),
                    }
                )
                stats["warning"] += 1

        # 3c. Check settled transactions have currency conversion if needed
        if tx.get("settled"):
            dest_id = psp.get("settlement_destination_id")
            dest_acct = treasury_accounts.get(dest_id) if dest_id else None
            if dest_acct and dest_acct.get("currency", "USD") != tx.get(
                "currency", "USD"
            ):
                # Check if treasury transaction has conversion
                ttx = await db.treasury_transactions.find_one(
                    {
                        "related_transaction_id": tx["transaction_id"],
                        "transaction_type": "psp_settlement",
                    },
                    {"_id": 0},
                )
                if ttx and not ttx.get("original_currency"):
                    findings.append(
                        {
                            "category": AuditCategory.PSP_SETTLEMENT,
                            "severity": AuditSeverity.CRITICAL,
                            "title": f"Missing currency conversion: {tx.get('reference', tx['transaction_id'])}",
                            "description": f"Settled {tx.get('currency','USD')} transaction to {dest_acct.get('currency','USD')} account without conversion",
                            "transaction_id": tx["transaction_id"],
                            "reference": tx.get("reference"),
                        }
                    )
                    stats["critical"] += 1
    stats["total_checks"] += 1

    # ---- 4. ANOMALY DETECTION ----
    # 4a. Large transactions
    anomaly_settings = (
        await db.app_settings.find_one({"setting_type": "audit"}, {"_id": 0}) or {}
    )
    large_threshold = anomaly_settings.get("large_transaction_threshold", 50000)

    for tx in all_txs:
        if tx.get("amount", 0) >= large_threshold:
            findings.append(
                {
                    "category": AuditCategory.ANOMALY_DETECTION,
                    "severity": AuditSeverity.INFO,
                    "title": f"Large transaction: {tx.get('reference', tx['transaction_id'])}",
                    "description": f"{tx.get('transaction_type', 'N/A').upper()} of {tx.get('amount', 0):,.2f} {tx.get('currency', 'USD')} for {tx.get('client_name', 'N/A')}",
                    "transaction_id": tx["transaction_id"],
                    "reference": tx.get("reference"),
                }
            )
            stats["info"] += 1

    # 4b. Round number detection (exact multiples of 10000)
    for tx in all_txs:
        amt = tx.get("amount", 0)
        if amt >= 10000 and amt % 10000 == 0:
            findings.append(
                {
                    "category": AuditCategory.ANOMALY_DETECTION,
                    "severity": AuditSeverity.INFO,
                    "title": f"Round amount: {tx.get('reference', tx['transaction_id'])}",
                    "description": f"Exact round amount {amt:,.0f} {tx.get('currency', 'USD')} - {tx.get('client_name', 'N/A')}",
                    "transaction_id": tx["transaction_id"],
                    "reference": tx.get("reference"),
                }
            )
            stats["info"] += 1
    stats["total_checks"] += 1

    # ---- 5. TREASURY BALANCE VERIFICATION ----
    for acct_id, acct in treasury_accounts.items():
        stored_balance = acct.get("balance", 0)

        # Sum all treasury transactions for this account
        ttxs = await db.treasury_transactions.find(
            {"account_id": acct_id}, {"_id": 0}
        ).to_list(50000)
        calculated_balance = sum(t.get("amount", 0) for t in ttxs)

        # Note: initial balance is not tracked in transactions, so we can only flag large discrepancies
        if len(ttxs) > 0 and abs(stored_balance - calculated_balance) > 1.0:
            findings.append(
                {
                    "category": AuditCategory.TREASURY_BALANCE,
                    "severity": AuditSeverity.WARNING,
                    "title": f"Balance discrepancy: {acct.get('account_name', acct_id)}",
                    "description": f"Stored balance: {stored_balance:,.2f} {acct.get('currency', 'USD')}, Sum of transactions: {calculated_balance:,.2f} {acct.get('currency', 'USD')}. Difference may include initial balance or manual adjustments.",
                    "account_id": acct_id,
                    "stored_balance": round(stored_balance, 2),
                    "calculated_balance": round(calculated_balance, 2),
                    "difference": round(stored_balance - calculated_balance, 2),
                }
            )
            stats["warning"] += 1
    stats["total_checks"] += 1

    stats["passed"] = max(
        0, stats["total_checks"] - stats["critical"] - stats["warning"]
    )
    health_score = max(0, 100 - (stats["critical"] * 15) - (stats["warning"] * 3))

    return {
        "scan_id": f"audit_{uuid.uuid4().hex[:12]}",
        "scanned_at": now.isoformat(),
        "health_score": min(100, health_score),
        "stats": stats,
        "findings": findings,
        "summary": {
            "total_transactions": len(all_txs),
            "psp_transactions": len(psp_txs),
            "treasury_accounts": len(treasury_accounts),
            "categories_checked": 5,
        },
    }


@api_router.post("/audit/run-scan")
async def run_audit_scan(user: dict = Depends(require_admin)):
    """Run a full audit scan and save results."""
    result = await run_audit_checks()

    # Save to DB
    await db.audit_scans.insert_one({**result})

    # Remove _id before returning
    result.pop("_id", None)
    return result


@api_router.get("/audit/latest")
async def get_latest_audit(user: dict = Depends(get_current_user)):
    """Get the latest audit scan result."""
    scan = await db.audit_scans.find_one({}, {"_id": 0}, sort=[("scanned_at", -1)])
    if not scan:
        return {"message": "No audit scans found. Run a scan first.", "scan_id": None}
    return scan


@api_router.get("/audit/history")
async def get_audit_history(user: dict = Depends(get_current_user), limit: int = 20):
    """Get audit scan history."""
    scans = (
        await db.audit_scans.find({}, {"_id": 0, "findings": 0})
        .sort("scanned_at", -1)
        .to_list(limit)
    )
    return scans


@api_router.get("/audit/settings")
async def get_audit_settings(user: dict = Depends(require_admin)):
    """Get audit module settings."""
    settings = await db.app_settings.find_one({"setting_type": "audit"}, {"_id": 0})
    if not settings:
        settings = {
            "setting_type": "audit",
            "large_transaction_threshold": 50000,
            "fx_deviation_threshold": 5,
            "auto_scan_enabled": False,
            "auto_scan_time": "02:00",
            "alert_emails": [],
        }
    return settings


class AuditSettingsUpdate(BaseModel):
    large_transaction_threshold: Optional[float] = None
    fx_deviation_threshold: Optional[float] = None
    auto_scan_enabled: Optional[bool] = None
    auto_scan_time: Optional[str] = None
    alert_emails: Optional[List[str]] = None


@api_router.put("/audit/settings")
async def update_audit_settings(
    settings: AuditSettingsUpdate, user: dict = Depends(require_admin)
):
    """Update audit module settings."""
    updates = {k: v for k, v in settings.model_dump().items() if v is not None}
    updates["setting_type"] = "audit"

    await db.app_settings.update_one(
        {"setting_type": "audit"}, {"$set": updates}, upsert=True
    )

    # Reschedule auto-scan if needed
    if settings.auto_scan_enabled is not None or settings.auto_scan_time is not None:
        await reschedule_audit_scan()

    return await db.app_settings.find_one({"setting_type": "audit"}, {"_id": 0})


async def send_audit_alert_email(result: dict):
    """Send audit alert email if issues found."""
    try:
        audit_settings = await db.app_settings.find_one(
            {"setting_type": "audit"}, {"_id": 0}
        )
        if not audit_settings or not audit_settings.get("alert_emails"):
            return

        smtp_settings = await db.app_settings.find_one(
            {"setting_type": "email"}, {"_id": 0}
        )
        if not smtp_settings or not smtp_settings.get("smtp_email"):
            return

        stats = result.get("stats", {})
        if stats.get("critical", 0) == 0 and stats.get("warning", 0) == 0:
            return  # No issues to report

        score = result.get("health_score", 100)
        color = "#ef4444" if score < 60 else "#f59e0b" if score < 80 else "#22c55e"

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0B0C10;color:#C5C6C7;padding:20px;border-radius:8px;">
            <h1 style="color:#66FCF1;margin-bottom:4px;">Miles Capitals - Audit Alert</h1>
            <p style="color:#888;margin-top:0;">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
            <div style="text-align:center;margin:20px 0;">
                <div style="display:inline-block;width:80px;height:80px;border-radius:50%;border:4px solid {color};line-height:80px;font-size:28px;font-weight:bold;color:{color};">{score}</div>
                <p style="color:#888;margin-top:8px;">Health Score</p>
            </div>
            <table style="width:100%;border-collapse:collapse;margin:16px 0;">
                <tr><td style="padding:8px;color:#ef4444;">Critical Issues</td><td style="padding:8px;text-align:right;font-weight:bold;">{stats.get('critical', 0)}</td></tr>
                <tr><td style="padding:8px;color:#f59e0b;">Warnings</td><td style="padding:8px;text-align:right;font-weight:bold;">{stats.get('warning', 0)}</td></tr>
                <tr><td style="padding:8px;color:#3b82f6;">Info</td><td style="padding:8px;text-align:right;font-weight:bold;">{stats.get('info', 0)}</td></tr>
            </table>
        """

        # Add critical findings
        criticals = [
            f for f in result.get("findings", []) if f.get("severity") == "critical"
        ]
        if criticals:
            html += '<h3 style="color:#ef4444;">Critical Findings</h3>'
            for f in criticals[:10]:
                html += f'<div style="background:#1a1a2e;padding:10px;margin:6px 0;border-left:3px solid #ef4444;border-radius:4px;">'
                html += f'<strong>{f.get("title","")}</strong><br/><span style="color:#999;font-size:13px;">{f.get("description","")}</span></div>'

        html += "</div>"

        await send_email(
            to_emails=audit_settings["alert_emails"],
            subject=f"Miles Capitals - Audit Alert (Score: {score}/100)",
            html_content=html,
            smtp_host=smtp_settings.get("smtp_host", "smtp.gmail.com"),
            smtp_port=smtp_settings.get("smtp_port", 587),
            smtp_email=smtp_settings["smtp_email"],
            smtp_password=smtp_settings["smtp_password"],
            smtp_from_email=smtp_settings.get(
                "smtp_from_email", smtp_settings["smtp_email"]
            ),
        )
        logger.info(
            f"Audit alert sent to {len(audit_settings['alert_emails'])} recipients"
        )
    except Exception as e:
        logger.error(f"Failed to send audit alert: {e}")


async def run_scheduled_audit():
    """Run scheduled audit scan and send alerts."""
    try:
        result = await run_audit_checks()
        await db.audit_scans.insert_one({**result})
        await send_audit_alert_email(result)
        logger.info(f"Scheduled audit complete. Score: {result['health_score']}/100")
    except Exception as e:
        logger.error(f"Scheduled audit failed: {e}")


async def reschedule_audit_scan():
    """Reschedule the automated audit scan."""
    global scheduler
    try:
        scheduler.remove_job("audit_scan")
    except:
        pass

    settings = await db.app_settings.find_one({"setting_type": "audit"}, {"_id": 0})
    if not settings or not settings.get("auto_scan_enabled"):
        logger.info("Auto audit scan disabled")
        return

    scan_time = settings.get("auto_scan_time", "02:00")
    hour, minute = map(int, scan_time.split(":"))

    scheduler.add_job(
        run_scheduled_audit,
        CronTrigger(hour=hour, minute=minute),
        id="audit_scan",
        replace_existing=True,
    )
    logger.info(f"Audit scan scheduled for {scan_time}")


# ============== FX RATE ENDPOINTS ==============
@api_router.get("/fx-rates")
async def get_fx_rates_endpoint(user: dict = Depends(get_current_user)):
    """Return current exchange rates (1 unit of currency = X USD)."""
    rates = await get_fx_rates()
    # Return a curated list of commonly used currencies
    popular = [
        "USD",
        "EUR",
        "GBP",
        "AED",
        "SAR",
        "INR",
        "JPY",
        "USDT",
        "CAD",
        "AUD",
        "CHF",
        "CNY",
        "SGD",
        "HKD",
        "KWD",
        "BHD",
        "OMR",
        "QAR",
        "MYR",
        "THB",
    ]
    filtered = {k: v for k, v in rates.items() if k in popular}
    # Always include all rates as a secondary field
    return {
        "rates": filtered,
        "all_rates": {k: v for k, v in sorted(rates.items())},
        "source": _fx_cache.get("source", "fallback"),
        "fetched_at": (
            _fx_cache.get("fetched_at", "").isoformat()
            if _fx_cache.get("fetched_at")
            else None
        ),
        "cache_ttl_minutes": int(FX_CACHE_TTL.total_seconds() / 60),
    }


@api_router.post("/fx-rates/refresh")
async def refresh_fx_rates(user: dict = Depends(require_admin)):
    """Force-refresh exchange rates from the live API."""
    _fx_cache["fetched_at"] = None  # invalidate cache
    rates = await get_fx_rates()
    return {
        "message": "Rates refreshed",
        "source": _fx_cache.get("source", "fallback"),
        "fetched_at": (
            _fx_cache.get("fetched_at", "").isoformat()
            if _fx_cache.get("fetched_at")
            else None
        ),
        "sample_rates": {
            k: rates.get(k) for k in ["USD", "EUR", "GBP", "AED", "INR"] if k in rates
        },
    }


@api_router.get("/fx-rates/convert")
async def convert_currency_endpoint(
    amount: float,
    from_currency: str,
    to_currency: str,
    user: dict = Depends(get_current_user),
):
    """Convert an amount between two currencies using live rates."""
    rates = await get_fx_rates()
    from_rate = rates.get(from_currency.upper())
    to_rate = rates.get(to_currency.upper())
    if from_rate is None or to_rate is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported currency: {from_currency if from_rate is None else to_currency}",
        )
    usd_amount = amount * from_rate
    converted = usd_amount / to_rate if to_rate else usd_amount
    return {
        "from_currency": from_currency.upper(),
        "to_currency": to_currency.upper(),
        "amount": amount,
        "converted_amount": round(converted, 4),
        "usd_equivalent": round(usd_amount, 4),
        "rate": round(from_rate / to_rate, 6) if to_rate else None,
    }


# ============== COMMISSION SETTINGS ENDPOINTS ==============
@api_router.get("/settings/commission")
async def get_commission_settings(user: dict = Depends(require_admin)):
    """Get global commission settings for deposits and withdrawals."""
    settings = await db.app_settings.find_one(
        {"setting_type": "commission"}, {"_id": 0}
    )
    if not settings:
        return {
            "deposit_commission_rate": 0.0,
            "withdrawal_commission_rate": 0.0,
            "commission_enabled": False,
        }
    return {
        "deposit_commission_rate": settings.get("deposit_commission_rate", 0.0),
        "withdrawal_commission_rate": settings.get("withdrawal_commission_rate", 0.0),
        "commission_enabled": settings.get("commission_enabled", False),
    }


@api_router.put("/settings/commission")
async def update_commission_settings(
    request: Request, user: dict = Depends(require_admin)
):
    """Update global commission settings."""
    data = await request.json()
    deposit_rate = float(data.get("deposit_commission_rate", 0))
    withdrawal_rate = float(data.get("withdrawal_commission_rate", 0))
    enabled = bool(data.get("commission_enabled", False))

    await db.app_settings.update_one(
        {"setting_type": "commission"},
        {
            "$set": {
                "setting_type": "commission",
                "deposit_commission_rate": deposit_rate,
                "withdrawal_commission_rate": withdrawal_rate,
                "commission_enabled": enabled,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "updated_by": user["user_id"],
            }
        },
        upsert=True,
    )
    return {
        "message": "Commission settings updated",
        "deposit_commission_rate": deposit_rate,
        "withdrawal_commission_rate": withdrawal_rate,
        "commission_enabled": enabled,
    }


# ============== LOGS MANAGEMENT ==============


@api_router.get("/logs")
async def get_all_logs(
    user: dict = Depends(require_admin),
    log_type: Optional[str] = None,
    action: Optional[str] = None,
    module: Optional[str] = None,
    user_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    skip: int = 0,
):
    """Get all logs with filtering"""
    query = {}

    if log_type:
        query["log_type"] = log_type
    if action:
        query["action"] = action
    if module:
        query["module"] = module
    if user_id:
        query["user_id"] = user_id
    if date_from:
        query["timestamp"] = {"$gte": date_from}
    if date_to:
        if "timestamp" in query:
            query["timestamp"]["$lte"] = date_to + "T23:59:59"
        else:
            query["timestamp"] = {"$lte": date_to + "T23:59:59"}
    if search:
        query["$or"] = [
            {"description": {"$regex": search, "$options": "i"}},
            {"user_name": {"$regex": search, "$options": "i"}},
            {"user_email": {"$regex": search, "$options": "i"}},
            {"reference_id": {"$regex": search, "$options": "i"}},
            {"module": {"$regex": search, "$options": "i"}},
        ]

    logs = (
        await db.system_logs.find(query, {"_id": 0})
        .sort("timestamp", -1)
        .skip(skip)
        .limit(limit)
        .to_list(length=limit)
    )
    total = await db.system_logs.count_documents(query)

    return {"logs": logs, "total": total, "limit": limit, "skip": skip}


@api_router.get("/logs/stats")
async def get_logs_stats(user: dict = Depends(require_admin)):
    """Get logs statistics"""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")

    total_logs = await db.system_logs.count_documents({})
    today_logs = await db.system_logs.count_documents({"timestamp": {"$gte": today}})

    # Logs by type
    activity_count = await db.system_logs.count_documents({"log_type": "activity"})
    auth_count = await db.system_logs.count_documents({"log_type": "auth"})
    audit_count = await db.system_logs.count_documents({"log_type": "audit"})
    error_count = await db.system_logs.count_documents({"log_type": "error"})

    # Failed logins in last 7 days
    failed_logins = await db.system_logs.count_documents(
        {"log_type": "auth", "action": "login_failed", "timestamp": {"$gte": week_ago}}
    )

    # Most active users
    pipeline = [
        {"$match": {"timestamp": {"$gte": week_ago}}},
        {"$group": {"_id": "$user_name", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    active_users = await db.system_logs.aggregate(pipeline).to_list(length=5)

    # Most common actions
    action_pipeline = [
        {"$match": {"timestamp": {"$gte": week_ago}}},
        {"$group": {"_id": "$action", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    common_actions = await db.system_logs.aggregate(action_pipeline).to_list(length=10)

    return {
        "total_logs": total_logs,
        "today_logs": today_logs,
        "by_type": {
            "activity": activity_count,
            "auth": auth_count,
            "audit": audit_count,
            "error": error_count,
        },
        "failed_logins_7d": failed_logins,
        "active_users": [
            {"user": u["_id"], "count": u["count"]} for u in active_users if u["_id"]
        ],
        "common_actions": [
            {"action": a["_id"], "count": a["count"]}
            for a in common_actions
            if a["_id"]
        ],
    }


@api_router.get("/logs/activity")
async def get_activity_logs(
    user: dict = Depends(require_admin),
    module: Optional[str] = None,
    user_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 100,
):
    """Get activity logs"""
    query = {"log_type": "activity"}
    if module:
        query["module"] = module
    if user_id:
        query["user_id"] = user_id
    if date_from:
        query["timestamp"] = {"$gte": date_from}
    if date_to:
        if "timestamp" in query:
            query["timestamp"]["$lte"] = date_to + "T23:59:59"
        else:
            query["timestamp"] = {"$lte": date_to + "T23:59:59"}

    logs = (
        await db.system_logs.find(query, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return {"logs": logs}


@api_router.get("/logs/auth")
async def get_auth_logs(
    user: dict = Depends(require_admin),
    action: Optional[str] = None,
    user_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 100,
):
    """Get authentication logs (login, logout, failed attempts)"""
    query = {"log_type": "auth"}
    if action:
        query["action"] = action
    if user_id:
        query["user_id"] = user_id
    if date_from:
        query["timestamp"] = {"$gte": date_from}
    if date_to:
        if "timestamp" in query:
            query["timestamp"]["$lte"] = date_to + "T23:59:59"
        else:
            query["timestamp"] = {"$lte": date_to + "T23:59:59"}

    logs = (
        await db.system_logs.find(query, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return {"logs": logs}


@api_router.get("/logs/audit")
async def get_audit_logs(
    user: dict = Depends(require_admin),
    module: Optional[str] = None,
    reference_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 100,
):
    """Get audit logs (financial changes)"""
    query = {"log_type": "audit"}
    if module:
        query["module"] = module
    if reference_id:
        query["reference_id"] = reference_id
    if date_from:
        query["timestamp"] = {"$gte": date_from}
    if date_to:
        if "timestamp" in query:
            query["timestamp"]["$lte"] = date_to + "T23:59:59"
        else:
            query["timestamp"] = {"$lte": date_to + "T23:59:59"}

    logs = (
        await db.system_logs.find(query, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return {"logs": logs}


@api_router.delete("/logs/clear")
async def clear_old_logs(user: dict = Depends(require_admin), days_to_keep: int = 90):
    """Clear logs older than specified days (default: 90 days)"""
    cutoff_date = (
        datetime.now(timezone.utc) - timedelta(days=days_to_keep)
    ).isoformat()
    result = await db.system_logs.delete_many({"timestamp": {"$lt": cutoff_date}})

    # Log this action
    await create_log(
        log_type="activity",
        action="delete",
        module="logs",
        user_id=user["user_id"],
        user_name=user["name"],
        user_email=user["email"],
        user_role=user["role"],
        description=f"Cleared {result.deleted_count} logs older than {days_to_keep} days",
    )

    return {
        "message": f"Deleted {result.deleted_count} logs older than {days_to_keep} days"
    }


# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_db_indexes():
    """Create database indexes and start scheduler"""
    try:
        # Unique index on transaction reference (sparse to allow null values)
        await db.transactions.create_index("reference", unique=True, sparse=True)
        # Index for duplicate detection queries
        await db.transactions.create_index(
            [
                ("client_id", 1),
                ("transaction_type", 1),
                ("amount", 1),
                ("created_at", -1),
            ]
        )
        logger.info("Database indexes created/verified successfully")
    except Exception as e:
        logger.warning(f"Index creation warning (may already exist): {e}")

    # Start scheduler and schedule daily report
    try:
        scheduler.start()
        await reschedule_daily_report()
        await reschedule_audit_scan()
        logger.info("Scheduler started successfully")
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")

    # Warm FX rate cache
    try:
        await get_fx_rates()
        logger.info(f"FX rates loaded (source: {_fx_cache.get('source', 'unknown')})")
    except Exception as e:
        logger.warning(f"FX rate warm-up failed: {e}")


@app.on_event("shutdown")
async def shutdown_db_client():
    scheduler.shutdown(wait=False)
    client.close()
