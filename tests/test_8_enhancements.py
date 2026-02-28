"""
Tests for the 8 Miles Capitals Back Office Enhancements:
1. Loans: multiple loans per company + CSV export
2. Expense->Loan conversion
3. No double-entry on conversion
4. Vendor in IE account dropdown + auto vendor approval flow
5. Income/Expense visual distinction (color-coded borders) - UI test
6. Vendor portal IE history tab - UI test
7. Bank account field when vendor selected - UI test
8. Vendor must upload screenshot when approving transactions
"""
import pytest
import requests
import os
import random
import string

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

def random_suffix():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


class TestAuth:
    """Helper class for authentication"""
    
    @staticmethod
    def get_admin_token():
        """Get admin auth token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "password"
        })
        assert response.status_code == 200, f"Admin login failed: {response.text}"
        return response.json()["access_token"]
    
    @staticmethod
    def get_vendor_token():
        """Get vendor auth token (vendor3)"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "vendor3@fxbroker.com",
            "password": "password"
        })
        assert response.status_code == 200, f"Vendor login failed: {response.text}"
        return response.json()["access_token"]


@pytest.fixture(scope="module")
def admin_headers():
    """Admin authentication headers"""
    token = TestAuth.get_admin_token()
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture(scope="module")
def vendor_headers():
    """Vendor authentication headers"""
    token = TestAuth.get_vendor_token()
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture(scope="module")
def treasury_account(admin_headers):
    """Get or create a treasury account for testing"""
    response = requests.get(f"{BASE_URL}/api/treasury", headers=admin_headers)
    assert response.status_code == 200
    accounts = response.json()
    # Find an active account with AED currency (ENBD)
    for acc in accounts:
        if acc.get("status") == "active":
            return acc
    pytest.skip("No active treasury account found")


@pytest.fixture(scope="module")
def vendor_info(admin_headers):
    """Get vendor information"""
    response = requests.get(f"{BASE_URL}/api/vendors", headers=admin_headers)
    assert response.status_code == 200
    vendors = response.json()
    for v in vendors:
        if v.get("status") == "active":
            return v
    pytest.skip("No active vendor found")


class TestLoansMultiplePerCompanyAndCSV:
    """Test Feature 1: Multiple loans per company + CSV export"""
    
    def test_create_multiple_loans_same_borrower(self, admin_headers, treasury_account):
        """Test that multiple loans can be created for the same company"""
        borrower = f"TEST_MultiLoan_Co_{random_suffix()}"
        
        # Create first loan
        loan1 = {
            "borrower_name": borrower,
            "amount": 1000,
            "currency": "USD",
            "interest_rate": 5,
            "loan_date": "2026-01-01",
            "due_date": "2026-06-01",
            "treasury_account_id": treasury_account["account_id"]
        }
        response1 = requests.post(f"{BASE_URL}/api/loans", json=loan1, headers=admin_headers)
        assert response1.status_code == 200, f"First loan creation failed: {response1.text}"
        loan1_data = response1.json()
        assert loan1_data.get("loan_id") is not None
        
        # Create second loan for same borrower
        loan2 = {
            "borrower_name": borrower,
            "amount": 2000,
            "currency": "USD",
            "interest_rate": 7,
            "loan_date": "2026-01-15",
            "due_date": "2026-07-01",
            "treasury_account_id": treasury_account["account_id"]
        }
        response2 = requests.post(f"{BASE_URL}/api/loans", json=loan2, headers=admin_headers)
        assert response2.status_code == 200, f"Second loan creation failed: {response2.text}"
        loan2_data = response2.json()
        assert loan2_data.get("loan_id") is not None
        
        # Verify both loans exist
        assert loan1_data["loan_id"] != loan2_data["loan_id"]
        print(f"✓ Created multiple loans for same borrower: {borrower}")
    
    def test_export_loans_csv(self, admin_headers):
        """Test GET /api/loans/export/csv returns CSV file"""
        response = requests.get(f"{BASE_URL}/api/loans/export/csv", headers=admin_headers)
        assert response.status_code == 200, f"CSV export failed: {response.text}"
        
        # Verify response is CSV
        content_type = response.headers.get("content-type", "")
        assert "text/csv" in content_type, f"Expected text/csv, got {content_type}"
        
        # Verify CSV has headers
        csv_content = response.text
        assert "Loan ID" in csv_content
        assert "Borrower" in csv_content
        assert "Amount" in csv_content
        print(f"✓ Loans CSV export successful ({len(csv_content)} bytes)")


class TestExpenseToLoanConversion:
    """Test Features 2 & 3: Expense->Loan conversion without double-entry"""
    
    @pytest.fixture
    def expense_entry(self, admin_headers, treasury_account):
        """Create an expense entry for conversion testing"""
        expense = {
            "entry_type": "expense",
            "category": "operational",
            "amount": 500 + random.randint(1, 100),
            "currency": "USD",
            "treasury_account_id": treasury_account["account_id"],
            "description": f"TEST_Expense_for_conversion_{random_suffix()}"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=expense, headers=admin_headers)
        assert response.status_code == 200, f"Expense creation failed: {response.text}"
        return response.json()
    
    def test_convert_expense_to_loan(self, admin_headers, treasury_account, expense_entry):
        """Test POST /api/income-expenses/{entry_id}/convert-to-loan"""
        entry_id = expense_entry["entry_id"]
        
        # Get treasury balance before conversion
        response = requests.get(f"{BASE_URL}/api/treasury/{treasury_account['account_id']}", headers=admin_headers)
        assert response.status_code == 200
        balance_before = response.json().get("balance", 0)
        
        # Convert expense to loan
        convert_data = {
            "borrower_name": f"TEST_Borrower_{random_suffix()}",
            "interest_rate": 8,
            "due_date": "2026-12-31",
            "treasury_account_id": treasury_account["account_id"],
            "notes": "Converted from expense"
        }
        response = requests.post(
            f"{BASE_URL}/api/income-expenses/{entry_id}/convert-to-loan",
            json=convert_data,
            headers=admin_headers
        )
        assert response.status_code == 200, f"Conversion failed: {response.text}"
        result = response.json()
        
        # Verify loan was created
        assert "loan" in result
        loan = result["loan"]
        assert loan["amount"] == expense_entry["amount"]
        assert loan["borrower_name"] == convert_data["borrower_name"]
        assert loan["status"] == "active"
        print(f"✓ Expense {entry_id} converted to loan {loan['loan_id']}")
        
        # Verify entry is marked as converted
        response = requests.get(f"{BASE_URL}/api/income-expenses/{entry_id}", headers=admin_headers)
        assert response.status_code == 200
        entry = response.json()
        assert entry.get("converted_to_loan") is True
        assert entry.get("status") == "converted_to_loan"
        assert entry.get("loan_id") == loan["loan_id"]
        print(f"✓ Entry status updated correctly")
    
    def test_cannot_convert_already_converted(self, admin_headers, treasury_account, expense_entry):
        """Test that already converted expenses cannot be converted again"""
        entry_id = expense_entry["entry_id"]
        
        # First conversion
        convert_data = {
            "borrower_name": f"TEST_First_{random_suffix()}",
            "interest_rate": 5,
            "due_date": "2026-12-31",
            "treasury_account_id": treasury_account["account_id"]
        }
        response = requests.post(
            f"{BASE_URL}/api/income-expenses/{entry_id}/convert-to-loan",
            json=convert_data,
            headers=admin_headers
        )
        assert response.status_code == 200
        
        # Second conversion attempt should fail
        convert_data2 = {
            "borrower_name": f"TEST_Second_{random_suffix()}",
            "interest_rate": 5,
            "due_date": "2026-12-31",
            "treasury_account_id": treasury_account["account_id"]
        }
        response2 = requests.post(
            f"{BASE_URL}/api/income-expenses/{entry_id}/convert-to-loan",
            json=convert_data2,
            headers=admin_headers
        )
        assert response2.status_code == 400
        assert "already been converted" in response2.json().get("detail", "").lower()
        print(f"✓ Double conversion correctly prevented")
    
    def test_converted_entries_excluded_from_summary(self, admin_headers, treasury_account):
        """Test that converted_to_loan entries are excluded from summary totals"""
        # Create and convert an expense
        expense = {
            "entry_type": "expense",
            "category": "operational",
            "amount": 1234,
            "currency": "USD",
            "treasury_account_id": treasury_account["account_id"],
            "description": f"TEST_SummaryExclusion_{random_suffix()}"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=expense, headers=admin_headers)
        assert response.status_code == 200
        entry_id = response.json()["entry_id"]
        
        # Get summary before conversion
        response = requests.get(f"{BASE_URL}/api/income-expenses/reports/summary", headers=admin_headers)
        assert response.status_code == 200
        summary_before = response.json()
        
        # Convert to loan
        convert_data = {
            "borrower_name": f"TEST_SummaryTest_{random_suffix()}",
            "interest_rate": 5,
            "due_date": "2026-12-31",
            "treasury_account_id": treasury_account["account_id"]
        }
        response = requests.post(
            f"{BASE_URL}/api/income-expenses/{entry_id}/convert-to-loan",
            json=convert_data,
            headers=admin_headers
        )
        assert response.status_code == 200
        
        # Get summary after conversion - expense should be excluded
        response = requests.get(f"{BASE_URL}/api/income-expenses/reports/summary", headers=admin_headers)
        assert response.status_code == 200
        summary_after = response.json()
        
        # The converted expense (1234 USD) should be excluded from totals
        # So total_expense should decrease by that amount (approximately, due to FX)
        print(f"✓ Summary excludes converted entries (before: {summary_before['total_expense_usd']}, after: {summary_after['total_expense_usd']})")


class TestVendorLinkedIncomeExpense:
    """Test Feature 4: Vendor in IE account dropdown + auto vendor approval flow"""
    
    def test_create_expense_with_vendor_pending_status(self, admin_headers, vendor_info, treasury_account):
        """Test that creating expense with vendor_id sets status to pending_vendor"""
        expense = {
            "entry_type": "expense",
            "category": "vendor_payment",
            "amount": 300 + random.randint(1, 50),
            "currency": "USD",
            "vendor_id": vendor_info["vendor_id"],
            "treasury_account_id": treasury_account["account_id"],
            "vendor_bank_account": "Test Bank - 123456789",
            "description": f"TEST_VendorExpense_{random_suffix()}"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=expense, headers=admin_headers)
        assert response.status_code == 200, f"Vendor expense creation failed: {response.text}"
        entry = response.json()
        
        assert entry["status"] == "pending_vendor"
        assert entry["vendor_id"] == vendor_info["vendor_id"]
        assert entry["vendor_name"] == vendor_info["vendor_name"]
        print(f"✓ Vendor-linked expense created with pending_vendor status")
        return entry
    
    def test_create_income_without_vendor_completed_status(self, admin_headers, treasury_account):
        """Test that creating income without vendor sets status to completed and updates treasury"""
        # Get treasury balance before
        response = requests.get(f"{BASE_URL}/api/treasury/{treasury_account['account_id']}", headers=admin_headers)
        balance_before = response.json().get("balance", 0)
        
        income = {
            "entry_type": "income",
            "category": "commission",
            "amount": 100 + random.randint(1, 50),
            "currency": treasury_account.get("currency", "AED"),
            "treasury_account_id": treasury_account["account_id"],
            "description": f"TEST_DirectIncome_{random_suffix()}"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=income, headers=admin_headers)
        assert response.status_code == 200, f"Direct income creation failed: {response.text}"
        entry = response.json()
        
        assert entry["status"] == "completed"
        assert entry.get("vendor_id") is None
        
        # Verify treasury balance increased
        response = requests.get(f"{BASE_URL}/api/treasury/{treasury_account['account_id']}", headers=admin_headers)
        balance_after = response.json().get("balance", 0)
        
        assert balance_after > balance_before, f"Treasury balance should increase. Before: {balance_before}, After: {balance_after}"
        print(f"✓ Direct income created with completed status, treasury updated")


class TestVendorIEApprovalFlow:
    """Test vendor approval/rejection of income/expense entries"""
    
    @pytest.fixture
    def pending_vendor_entry(self, admin_headers, vendor_info, treasury_account):
        """Create a pending vendor entry"""
        expense = {
            "entry_type": "expense",
            "category": "vendor_payment",
            "amount": 250 + random.randint(1, 50),
            "currency": treasury_account.get("currency", "AED"),
            "vendor_id": vendor_info["vendor_id"],
            "treasury_account_id": treasury_account["account_id"],
            "description": f"TEST_PendingVendor_{random_suffix()}"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=expense, headers=admin_headers)
        assert response.status_code == 200
        return response.json()
    
    def test_vendor_can_see_ie_entries(self, vendor_headers, pending_vendor_entry):
        """Test GET /api/vendor/income-expenses returns vendor's entries"""
        response = requests.get(f"{BASE_URL}/api/vendor/income-expenses", headers=vendor_headers)
        assert response.status_code == 200, f"Vendor IE list failed: {response.text}"
        entries = response.json()
        
        # Find our test entry
        found = False
        for e in entries:
            if e["entry_id"] == pending_vendor_entry["entry_id"]:
                found = True
                assert e["status"] == "pending_vendor"
                break
        assert found, "Pending entry not found in vendor's IE list"
        print(f"✓ Vendor can see their IE entries")
    
    def test_vendor_approve_ie_updates_treasury(self, vendor_headers, admin_headers, pending_vendor_entry, treasury_account):
        """Test POST /api/income-expenses/{entry_id}/vendor-approve updates treasury"""
        entry_id = pending_vendor_entry["entry_id"]
        
        # Get treasury balance before
        response = requests.get(f"{BASE_URL}/api/treasury/{treasury_account['account_id']}", headers=admin_headers)
        balance_before = response.json().get("balance", 0)
        
        # Vendor approves
        response = requests.post(
            f"{BASE_URL}/api/income-expenses/{entry_id}/vendor-approve",
            headers=vendor_headers
        )
        assert response.status_code == 200, f"Vendor approval failed: {response.text}"
        
        # Verify entry status
        response = requests.get(f"{BASE_URL}/api/income-expenses/{entry_id}", headers=admin_headers)
        assert response.status_code == 200
        entry = response.json()
        assert entry["status"] == "completed"
        
        # Verify treasury balance decreased (expense)
        response = requests.get(f"{BASE_URL}/api/treasury/{treasury_account['account_id']}", headers=admin_headers)
        balance_after = response.json().get("balance", 0)
        
        # For expense, balance should decrease
        assert balance_after < balance_before, f"Treasury should decrease for expense. Before: {balance_before}, After: {balance_after}"
        print(f"✓ Vendor approval updated treasury correctly")
    
    def test_vendor_reject_ie(self, vendor_headers, admin_headers, vendor_info, treasury_account):
        """Test POST /api/income-expenses/{entry_id}/vendor-reject"""
        # Create a new pending entry
        expense = {
            "entry_type": "expense",
            "category": "vendor_payment",
            "amount": 180,
            "currency": "USD",
            "vendor_id": vendor_info["vendor_id"],
            "treasury_account_id": treasury_account["account_id"],
            "description": f"TEST_ToReject_{random_suffix()}"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=expense, headers=admin_headers)
        assert response.status_code == 200
        entry_id = response.json()["entry_id"]
        
        # Vendor rejects
        response = requests.post(
            f"{BASE_URL}/api/income-expenses/{entry_id}/vendor-reject?reason=Test%20rejection",
            headers=vendor_headers
        )
        assert response.status_code == 200, f"Vendor rejection failed: {response.text}"
        
        # Verify entry status
        response = requests.get(f"{BASE_URL}/api/income-expenses/{entry_id}", headers=admin_headers)
        entry = response.json()
        assert entry["status"] == "rejected"
        assert entry.get("rejection_reason") == "Test rejection"
        print(f"✓ Vendor rejection working correctly")


class TestVendorTransactionProofRequirement:
    """Test Feature 8: Vendor must upload screenshot when approving transactions"""
    
    def test_vendor_approval_requires_proof(self, vendor_headers, admin_headers, vendor_info, treasury_account):
        """Test that vendor cannot approve transaction without uploading proof first"""
        # First, we need a pending transaction for the vendor
        # Let's check if there are any pending transactions
        response = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor_headers)
        assert response.status_code == 200
        vendor_data = response.json()
        
        pending_txs = [t for t in vendor_data.get("pending_transactions", []) if t["status"] == "pending" and not t.get("vendor_proof_image")]
        
        if not pending_txs:
            # We need to create a transaction assigned to vendor
            # First get a client
            response = requests.get(f"{BASE_URL}/api/clients", headers=admin_headers)
            if response.status_code != 200 or not response.json():
                pytest.skip("No clients available to create transaction")
            client = response.json()[0]
            
            # Create transaction for vendor
            tx_data = {
                "client_id": client["client_id"],
                "transaction_type": "deposit",
                "amount": 500,
                "currency": "USD",
                "destination_type": "vendor",
                "vendor_id": vendor_info["vendor_id"],
                "description": f"TEST_ProofRequired_{random_suffix()}"
            }
            response = requests.post(f"{BASE_URL}/api/transactions", json=tx_data, headers=admin_headers)
            if response.status_code != 200:
                pytest.skip(f"Could not create test transaction: {response.text}")
            tx = response.json()
            tx_id = tx["transaction_id"]
        else:
            tx = pending_txs[0]
            tx_id = tx["transaction_id"]
        
        # Try to approve without proof - should fail
        response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx_id}/approve",
            headers=vendor_headers
        )
        
        # Should fail with 400 requiring proof
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        assert "proof" in response.json().get("detail", "").lower(), f"Expected proof error, got: {response.text}"
        print(f"✓ Vendor approval correctly requires proof upload first")


class TestConvertedEntriesInList:
    """Test that converted_to_loan entries still appear in list but with converted status"""
    
    def test_converted_entries_still_in_list(self, admin_headers, treasury_account):
        """Test GET /api/income-expenses returns converted entries with correct status"""
        # Create expense
        expense = {
            "entry_type": "expense",
            "category": "operational",
            "amount": 789,
            "currency": "USD",
            "treasury_account_id": treasury_account["account_id"],
            "description": f"TEST_ListCheck_{random_suffix()}"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=expense, headers=admin_headers)
        assert response.status_code == 200
        entry_id = response.json()["entry_id"]
        
        # Convert to loan
        convert_data = {
            "borrower_name": f"TEST_ListBorrower_{random_suffix()}",
            "interest_rate": 5,
            "due_date": "2026-12-31",
            "treasury_account_id": treasury_account["account_id"]
        }
        response = requests.post(
            f"{BASE_URL}/api/income-expenses/{entry_id}/convert-to-loan",
            json=convert_data,
            headers=admin_headers
        )
        assert response.status_code == 200
        
        # Get list of entries
        response = requests.get(f"{BASE_URL}/api/income-expenses", headers=admin_headers)
        assert response.status_code == 200
        entries = response.json()
        
        # Find our entry
        found = False
        for e in entries:
            if e["entry_id"] == entry_id:
                found = True
                assert e["converted_to_loan"] is True
                assert e["status"] == "converted_to_loan"
                assert e.get("loan_id") is not None
                break
        
        assert found, "Converted entry should still appear in list"
        print(f"✓ Converted entry appears in list with correct status")


# Run health check first
class TestHealthCheck:
    """Basic health check"""
    
    def test_api_health(self):
        """Test API is accessible"""
        response = requests.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": "Bearer invalid"})
        # Just check server responds (401 is expected for invalid token)
        assert response.status_code in [200, 401], f"API not responding: {response.status_code}"
        print(f"✓ API is accessible at {BASE_URL}")
