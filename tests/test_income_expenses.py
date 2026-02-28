"""
Income & Expenses Feature Backend Tests

Tests for:
- GET /api/income-expenses - List all income/expense entries with filters
- GET /api/income-expenses/{entry_id} - Get single entry
- POST /api/income-expenses - Create income or expense entry
- PUT /api/income-expenses/{entry_id} - Update entry
- DELETE /api/income-expenses/{entry_id} - Delete entry (reverses treasury balance)
- GET /api/income-expenses/reports/summary - Category breakdown report
- GET /api/income-expenses/reports/monthly - Monthly P&L report
- GET /api/income-expenses/categories - Get available categories
"""

import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')
TEST_EMAIL = "admin@fxbroker.com"
TEST_PASSWORD = "admin123"


@pytest.fixture(scope="module")
def auth_token():
    """Get authentication token for admin user"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    })
    assert response.status_code == 200, f"Login failed: {response.text}"
    data = response.json()
    assert "access_token" in data
    return data["access_token"]


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Returns headers with auth token"""
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }


@pytest.fixture(scope="module")
def test_treasury_account(auth_headers):
    """Create a test treasury account with initial balance for testing"""
    # First, try to find an existing active treasury account
    response = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers)
    assert response.status_code == 200
    accounts = response.json()
    
    # Look for an active account with enough balance for testing
    for acc in accounts:
        if acc.get("status") == "active" and acc.get("balance", 0) >= 1000:
            return acc
    
    # If no suitable account found, create one for testing
    create_payload = {
        "account_name": "TEST_Income_Expense_Account",
        "account_type": "bank",
        "bank_name": "Test Bank",
        "account_number": "9876543210",
        "currency": "USD",
        "description": "Test account for income/expense testing"
    }
    
    response = requests.post(f"{BASE_URL}/api/treasury", headers=auth_headers, json=create_payload)
    assert response.status_code == 200, f"Failed to create test treasury account: {response.text}"
    account = response.json()
    
    # Add some initial balance by creating an income entry
    return account


class TestIncomeExpensesAuth:
    """Test authentication requirements"""
    
    def test_list_entries_requires_auth(self):
        """GET /api/income-expenses should require authentication"""
        response = requests.get(f"{BASE_URL}/api/income-expenses")
        assert response.status_code == 401
    
    def test_create_entry_requires_auth(self):
        """POST /api/income-expenses should require authentication"""
        response = requests.post(f"{BASE_URL}/api/income-expenses", json={
            "entry_type": "income",
            "category": "commission",
            "amount": 100,
            "treasury_account_id": "test"
        })
        assert response.status_code == 401
    
    def test_delete_entry_requires_auth(self):
        """DELETE /api/income-expenses/{id} should require authentication"""
        response = requests.delete(f"{BASE_URL}/api/income-expenses/test123")
        assert response.status_code == 401


class TestIncomeCreation:
    """Test income entry creation"""
    
    def test_create_income_commission(self, auth_headers, test_treasury_account):
        """Create income entry with commission category"""
        account_id = test_treasury_account["account_id"]
        initial_balance = test_treasury_account.get("balance", 0)
        
        # Get current balance
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        if response.status_code == 200:
            initial_balance = response.json().get("balance", 0)
        
        payload = {
            "entry_type": "income",
            "category": "commission",
            "amount": 1000.50,
            "currency": "USD",
            "treasury_account_id": account_id,
            "description": "TEST_Commission income from trading",
            "reference": "INV-TEST-001",
            "date": "2026-01-15"
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 200, f"Failed to create income: {response.text}"
        
        data = response.json()
        assert data["entry_type"] == "income"
        assert data["category"] == "commission"
        assert data["amount"] == 1000.50
        assert data["currency"] == "USD"
        assert "entry_id" in data
        assert data["treasury_account_id"] == account_id
        
        # Verify treasury balance increased
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        assert response.status_code == 200
        new_balance = response.json().get("balance", 0)
        assert new_balance >= initial_balance + 1000.50 - 0.01, "Treasury balance should increase for income"
    
    def test_create_income_service_fee(self, auth_headers, test_treasury_account):
        """Create income entry with service fee category"""
        payload = {
            "entry_type": "income",
            "category": "service_fee",
            "amount": 250,
            "currency": "USD",
            "treasury_account_id": test_treasury_account["account_id"],
            "description": "TEST_Monthly service fee",
            "reference": "SF-TEST-001"
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["entry_type"] == "income"
        assert data["category"] == "service_fee"
    
    def test_create_income_with_custom_category(self, auth_headers, test_treasury_account):
        """Create income entry with 'other' category and custom name"""
        payload = {
            "entry_type": "income",
            "category": "other",
            "custom_category": "Referral Bonus",
            "amount": 500,
            "currency": "USD",
            "treasury_account_id": test_treasury_account["account_id"],
            "description": "TEST_Referral bonus payment"
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["category"] == "other"
        assert data["custom_category"] == "Referral Bonus"
    
    def test_create_income_invalid_treasury(self, auth_headers):
        """Creating income with invalid treasury account should fail"""
        payload = {
            "entry_type": "income",
            "category": "commission",
            "amount": 100,
            "currency": "USD",
            "treasury_account_id": "invalid_account_id",
            "description": "Test"
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 404
    
    def test_create_income_invalid_amount(self, auth_headers, test_treasury_account):
        """Creating income with zero or negative amount should fail"""
        payload = {
            "entry_type": "income",
            "category": "commission",
            "amount": 0,
            "currency": "USD",
            "treasury_account_id": test_treasury_account["account_id"]
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 400


class TestExpenseCreation:
    """Test expense entry creation"""
    
    def test_create_expense_bank_fee(self, auth_headers, test_treasury_account):
        """Create expense entry with bank fee category"""
        account_id = test_treasury_account["account_id"]
        
        # Get current balance first
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        initial_balance = response.json().get("balance", 0) if response.status_code == 200 else 0
        
        # Skip if insufficient balance
        if initial_balance < 50:
            pytest.skip("Insufficient treasury balance for expense test")
        
        payload = {
            "entry_type": "expense",
            "category": "bank_fee",
            "amount": 25.50,
            "currency": "USD",
            "treasury_account_id": account_id,
            "description": "TEST_Monthly bank fee",
            "reference": "BF-TEST-001"
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 200, f"Failed to create expense: {response.text}"
        
        data = response.json()
        assert data["entry_type"] == "expense"
        assert data["category"] == "bank_fee"
        assert data["amount"] == 25.50
        
        # Verify treasury balance decreased
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        assert response.status_code == 200
        new_balance = response.json().get("balance", 0)
        assert new_balance <= initial_balance - 25.50 + 0.01, "Treasury balance should decrease for expense"
    
    def test_create_expense_operational(self, auth_headers, test_treasury_account):
        """Create expense entry with operational category"""
        account_id = test_treasury_account["account_id"]
        
        # Get current balance first
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        initial_balance = response.json().get("balance", 0) if response.status_code == 200 else 0
        
        if initial_balance < 100:
            pytest.skip("Insufficient treasury balance for expense test")
        
        payload = {
            "entry_type": "expense",
            "category": "operational",
            "amount": 75,
            "currency": "USD",
            "treasury_account_id": account_id,
            "description": "TEST_Office supplies"
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["entry_type"] == "expense"
        assert data["category"] == "operational"
    
    def test_create_expense_insufficient_balance(self, auth_headers, test_treasury_account):
        """Creating expense with insufficient treasury balance should fail"""
        account_id = test_treasury_account["account_id"]
        
        # Get current balance
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        current_balance = response.json().get("balance", 0) if response.status_code == 200 else 0
        
        # Try to create expense larger than balance
        payload = {
            "entry_type": "expense",
            "category": "operational",
            "amount": current_balance + 10000,  # More than available
            "currency": "USD",
            "treasury_account_id": account_id,
            "description": "TEST_Should fail"
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 400
        assert "insufficient" in response.json().get("detail", "").lower() or "balance" in response.json().get("detail", "").lower()


class TestEntryListing:
    """Test entry listing and filtering"""
    
    def test_list_all_entries(self, auth_headers):
        """GET /api/income-expenses should return entries"""
        response = requests.get(f"{BASE_URL}/api/income-expenses", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
    
    def test_filter_by_entry_type_income(self, auth_headers):
        """Filter entries by type=income"""
        response = requests.get(f"{BASE_URL}/api/income-expenses?entry_type=income", headers=auth_headers)
        assert response.status_code == 200
        
        entries = response.json()
        for entry in entries:
            assert entry["entry_type"] == "income"
    
    def test_filter_by_entry_type_expense(self, auth_headers):
        """Filter entries by type=expense"""
        response = requests.get(f"{BASE_URL}/api/income-expenses?entry_type=expense", headers=auth_headers)
        assert response.status_code == 200
        
        entries = response.json()
        for entry in entries:
            assert entry["entry_type"] == "expense"
    
    def test_filter_by_treasury_account(self, auth_headers, test_treasury_account):
        """Filter entries by treasury account"""
        account_id = test_treasury_account["account_id"]
        response = requests.get(f"{BASE_URL}/api/income-expenses?treasury_account_id={account_id}", headers=auth_headers)
        assert response.status_code == 200
        
        entries = response.json()
        for entry in entries:
            assert entry["treasury_account_id"] == account_id
    
    def test_filter_by_date_range(self, auth_headers):
        """Filter entries by date range"""
        response = requests.get(
            f"{BASE_URL}/api/income-expenses?start_date=2026-01-01&end_date=2026-12-31",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        entries = response.json()
        assert isinstance(entries, list)


class TestDeleteEntry:
    """Test entry deletion and treasury balance reversal"""
    
    def test_delete_income_entry_reverses_balance(self, auth_headers, test_treasury_account):
        """Deleting income entry should reverse (deduct from) treasury balance"""
        account_id = test_treasury_account["account_id"]
        
        # Create an income entry first
        payload = {
            "entry_type": "income",
            "category": "interest",
            "amount": 100,
            "currency": "USD",
            "treasury_account_id": account_id,
            "description": "TEST_Delete test income"
        }
        
        create_response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert create_response.status_code == 200
        entry = create_response.json()
        entry_id = entry["entry_id"]
        
        # Get balance after income
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        balance_after_income = response.json().get("balance", 0)
        
        # Delete the entry
        delete_response = requests.delete(f"{BASE_URL}/api/income-expenses/{entry_id}", headers=auth_headers)
        assert delete_response.status_code == 200, f"Delete failed: {delete_response.text}"
        
        # Verify balance was reversed (decreased)
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        balance_after_delete = response.json().get("balance", 0)
        
        assert abs(balance_after_delete - (balance_after_income - 100)) < 0.01, "Balance should decrease by income amount after delete"
    
    def test_delete_expense_entry_reverses_balance(self, auth_headers, test_treasury_account):
        """Deleting expense entry should reverse (credit to) treasury balance"""
        account_id = test_treasury_account["account_id"]
        
        # Get initial balance
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        initial_balance = response.json().get("balance", 0)
        
        if initial_balance < 50:
            # Need to add some balance first
            income_payload = {
                "entry_type": "income",
                "category": "commission",
                "amount": 200,
                "currency": "USD",
                "treasury_account_id": account_id,
                "description": "TEST_Setup income"
            }
            requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=income_payload)
            
            response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
            initial_balance = response.json().get("balance", 0)
        
        # Create an expense entry
        payload = {
            "entry_type": "expense",
            "category": "bank_fee",
            "amount": 30,
            "currency": "USD",
            "treasury_account_id": account_id,
            "description": "TEST_Delete test expense"
        }
        
        create_response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert create_response.status_code == 200
        entry = create_response.json()
        entry_id = entry["entry_id"]
        
        # Get balance after expense
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        balance_after_expense = response.json().get("balance", 0)
        
        # Delete the entry
        delete_response = requests.delete(f"{BASE_URL}/api/income-expenses/{entry_id}", headers=auth_headers)
        assert delete_response.status_code == 200
        
        # Verify balance was reversed (increased)
        response = requests.get(f"{BASE_URL}/api/treasury/{account_id}", headers=auth_headers)
        balance_after_delete = response.json().get("balance", 0)
        
        assert abs(balance_after_delete - (balance_after_expense + 30)) < 0.01, "Balance should increase by expense amount after delete"
    
    def test_delete_nonexistent_entry(self, auth_headers):
        """Deleting non-existent entry should return 404"""
        response = requests.delete(f"{BASE_URL}/api/income-expenses/nonexistent_id", headers=auth_headers)
        assert response.status_code == 404


class TestReports:
    """Test reporting endpoints"""
    
    def test_get_summary_report(self, auth_headers):
        """GET /api/income-expenses/reports/summary should return summary"""
        response = requests.get(f"{BASE_URL}/api/income-expenses/reports/summary", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "total_income_usd" in data
        assert "total_expense_usd" in data
        assert "net_profit_usd" in data
        assert "income_by_category" in data
        assert "expense_by_category" in data
        assert "entry_count" in data
        
        # Verify net_profit calculation
        expected_net = data["total_income_usd"] - data["total_expense_usd"]
        assert abs(data["net_profit_usd"] - expected_net) < 0.01
    
    def test_summary_report_with_date_filter(self, auth_headers):
        """Summary report should support date filtering"""
        response = requests.get(
            f"{BASE_URL}/api/income-expenses/reports/summary?start_date=2026-01-01&end_date=2026-12-31",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "total_income_usd" in data
    
    def test_get_monthly_report(self, auth_headers):
        """GET /api/income-expenses/reports/monthly should return monthly P&L"""
        response = requests.get(f"{BASE_URL}/api/income-expenses/reports/monthly", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 12  # 12 months
        
        # Check structure of monthly data
        for month_data in data:
            assert "month" in month_data
            assert "income" in month_data
            assert "expense" in month_data
            assert "net" in month_data
            
            # Verify net calculation
            expected_net = month_data["income"] - month_data["expense"]
            assert abs(month_data["net"] - expected_net) < 0.01
    
    def test_monthly_report_with_year(self, auth_headers):
        """Monthly report should support year parameter"""
        response = requests.get(f"{BASE_URL}/api/income-expenses/reports/monthly?year=2026", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert len(data) == 12
        
        # All months should be from 2026
        for month_data in data:
            assert month_data["month"].startswith("2026-")
    
    def test_get_categories(self, auth_headers):
        """GET /api/income-expenses/categories should return available categories"""
        response = requests.get(f"{BASE_URL}/api/income-expenses/categories", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "income_categories" in data
        assert "expense_categories" in data
        
        # Check income categories
        income_cats = [c["value"] for c in data["income_categories"]]
        assert "commission" in income_cats
        assert "service_fee" in income_cats
        assert "interest" in income_cats
        assert "other" in income_cats
        
        # Check expense categories
        expense_cats = [c["value"] for c in data["expense_categories"]]
        assert "bank_fee" in expense_cats
        assert "operational" in expense_cats


class TestMultiCurrency:
    """Test multi-currency support"""
    
    def test_create_income_non_usd_currency(self, auth_headers, test_treasury_account):
        """Create income in EUR currency should convert to USD"""
        payload = {
            "entry_type": "income",
            "category": "commission",
            "amount": 100,
            "currency": "EUR",
            "treasury_account_id": test_treasury_account["account_id"],
            "description": "TEST_EUR income"
        }
        
        response = requests.post(f"{BASE_URL}/api/income-expenses", headers=auth_headers, json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["currency"] == "EUR"
        assert data["amount"] == 100
        assert "amount_usd" in data
        # EUR to USD rate is 1.08, so 100 EUR = 108 USD
        assert data["amount_usd"] > 100  # Should be greater than original amount


# Cleanup after tests
@pytest.fixture(scope="module", autouse=True)
def cleanup(auth_headers):
    """Cleanup test entries after all tests complete"""
    yield
    # Delete all TEST_ entries
    response = requests.get(f"{BASE_URL}/api/income-expenses?limit=500", headers=auth_headers)
    if response.status_code == 200:
        entries = response.json()
        for entry in entries:
            if entry.get("description", "").startswith("TEST_"):
                requests.delete(f"{BASE_URL}/api/income-expenses/{entry['entry_id']}", headers=auth_headers)
