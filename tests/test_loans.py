"""
Test suite for Loan Management feature
Tests: Create loan, record repayments, status updates, treasury balance changes, delete loan, summary report
"""
import pytest
import requests
import os
import uuid
from datetime import datetime, timedelta

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestLoanManagement:
    """Comprehensive tests for Loan Management feature"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup - login and get auth token"""
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        
        # Login as admin
        login_response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "admin123"
        })
        
        if login_response.status_code != 200:
            pytest.skip("Could not authenticate - skipping tests")
        
        token = login_response.json().get("access_token")
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        
        # Get treasury accounts for tests
        treasury_resp = self.session.get(f"{BASE_URL}/api/treasury")
        if treasury_resp.status_code == 200:
            self.treasury_accounts = treasury_resp.json()
        else:
            self.treasury_accounts = []
        
        yield
        
        # Cleanup - delete test loans
        loans_resp = self.session.get(f"{BASE_URL}/api/loans?limit=1000")
        if loans_resp.status_code == 200:
            for loan in loans_resp.json():
                if loan.get("borrower_name", "").startswith("TEST_"):
                    # Delete repayments first, then loan
                    self.session.delete(f"{BASE_URL}/api/loans/{loan['loan_id']}")

    # ============== AUTH TESTS ==============
    
    def test_auth_required_get_loans(self):
        """Test GET /api/loans requires authentication"""
        resp = requests.get(f"{BASE_URL}/api/loans")
        assert resp.status_code == 401, "Should require auth"
    
    def test_auth_required_create_loan(self):
        """Test POST /api/loans requires authentication"""
        resp = requests.post(f"{BASE_URL}/api/loans", json={
            "borrower_name": "Test",
            "amount": 1000,
            "currency": "USD",
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
            "treasury_account_id": "treasury_test"
        })
        assert resp.status_code == 401, "Should require auth"
    
    def test_auth_required_loan_summary(self):
        """Test GET /api/loans/reports/summary requires authentication"""
        resp = requests.get(f"{BASE_URL}/api/loans/reports/summary")
        assert resp.status_code == 401, "Should require auth"
    
    # ============== GET LOANS TESTS ==============
    
    def test_get_loans_empty_or_list(self):
        """Test GET /api/loans returns list"""
        resp = self.session.get(f"{BASE_URL}/api/loans")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list), "Should return list of loans"
    
    def test_get_loans_with_status_filter(self):
        """Test GET /api/loans?status=active filters by status"""
        resp = self.session.get(f"{BASE_URL}/api/loans?status=active")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # All returned should be active (if any)
        for loan in data:
            assert loan.get("status") == "active" or loan.get("status") == "overdue", f"Unexpected status: {loan.get('status')}"
    
    # ============== CREATE LOAN TESTS ==============
    
    def test_create_loan_success(self):
        """Test POST /api/loans creates loan and deducts from treasury"""
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        # Find an active treasury account with sufficient balance
        treasury = None
        for acc in self.treasury_accounts:
            if acc.get("status") == "active" and acc.get("balance", 0) >= 1000:
                treasury = acc
                break
        
        if not treasury:
            pytest.skip("No treasury account with sufficient balance")
        
        initial_balance = treasury.get("balance", 0)
        
        loan_date = datetime.now().strftime("%Y-%m-%d")
        due_date = (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d")
        
        payload = {
            "borrower_name": f"TEST_Company_{uuid.uuid4().hex[:8]}",
            "amount": 1000,
            "currency": treasury.get("currency", "USD"),
            "interest_rate": 12,  # 12% annual
            "loan_date": loan_date,
            "due_date": due_date,
            "repayment_mode": "lump_sum",
            "treasury_account_id": treasury["account_id"],
            "notes": "Test loan for pytest"
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans", json=payload)
        assert resp.status_code == 200, f"Create loan failed: {resp.text}"
        
        data = resp.json()
        assert "loan_id" in data, "Should return loan_id"
        assert data["borrower_name"] == payload["borrower_name"]
        assert data["amount"] == 1000
        assert data["status"] == "active"
        assert data["interest_rate"] == 12
        assert data.get("total_interest") is not None, "Should calculate interest"
        
        # Store for cleanup and further tests
        self.test_loan_id = data["loan_id"]
        self.test_treasury_id = treasury["account_id"]
        
        # Verify treasury balance was deducted
        treasury_resp = self.session.get(f"{BASE_URL}/api/treasury/{treasury['account_id']}")
        if treasury_resp.status_code == 200:
            new_balance = treasury_resp.json().get("balance", 0)
            assert new_balance == initial_balance - 1000, f"Treasury balance not deducted. Expected {initial_balance - 1000}, got {new_balance}"
        
        return data
    
    def test_create_loan_insufficient_balance(self):
        """Test POST /api/loans rejects if treasury has insufficient balance"""
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        treasury = self.treasury_accounts[0]
        balance = treasury.get("balance", 0)
        
        payload = {
            "borrower_name": "TEST_InsufficientBalance",
            "amount": balance + 999999,  # More than available
            "currency": treasury.get("currency", "USD"),
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
            "treasury_account_id": treasury["account_id"]
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans", json=payload)
        assert resp.status_code == 400, "Should reject insufficient balance"
        assert "Insufficient" in resp.json().get("detail", "")
    
    def test_create_loan_invalid_treasury(self):
        """Test POST /api/loans rejects invalid treasury account"""
        payload = {
            "borrower_name": "TEST_InvalidTreasury",
            "amount": 100,
            "currency": "USD",
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
            "treasury_account_id": "invalid_treasury_id"
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans", json=payload)
        assert resp.status_code == 404, "Should reject invalid treasury"
    
    def test_create_loan_zero_amount(self):
        """Test POST /api/loans rejects zero/negative amount"""
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        treasury = self.treasury_accounts[0]
        
        payload = {
            "borrower_name": "TEST_ZeroAmount",
            "amount": 0,
            "currency": "USD",
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
            "treasury_account_id": treasury["account_id"]
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans", json=payload)
        assert resp.status_code == 400, "Should reject zero amount"
    
    def test_create_loan_with_installments(self):
        """Test POST /api/loans with installment repayment mode"""
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        # Find treasury with balance
        treasury = None
        for acc in self.treasury_accounts:
            if acc.get("status") == "active" and acc.get("balance", 0) >= 500:
                treasury = acc
                break
        
        if not treasury:
            pytest.skip("No treasury account with sufficient balance")
        
        payload = {
            "borrower_name": f"TEST_Installment_{uuid.uuid4().hex[:8]}",
            "amount": 500,
            "currency": treasury.get("currency", "USD"),
            "interest_rate": 10,
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": (datetime.now() + timedelta(days=180)).strftime("%Y-%m-%d"),
            "repayment_mode": "installments",
            "installment_amount": 100,
            "installment_frequency": "monthly",
            "treasury_account_id": treasury["account_id"]
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans", json=payload)
        assert resp.status_code == 200, f"Create installment loan failed: {resp.text}"
        
        data = resp.json()
        assert data["repayment_mode"] == "installments"
        assert data["installment_amount"] == 100
        assert data["installment_frequency"] == "monthly"
    
    # ============== GET LOAN DETAIL TESTS ==============
    
    def test_get_loan_detail(self):
        """Test GET /api/loans/{loan_id} returns loan with repayment history"""
        # First create a loan
        loan = self.test_create_loan_success()
        
        resp = self.session.get(f"{BASE_URL}/api/loans/{loan['loan_id']}")
        assert resp.status_code == 200
        
        data = resp.json()
        assert data["loan_id"] == loan["loan_id"]
        assert "repayments" in data, "Should include repayment history"
        assert "outstanding_balance" in data
        assert "source_treasury_name" in data
    
    def test_get_loan_not_found(self):
        """Test GET /api/loans/{loan_id} returns 404 for invalid ID"""
        resp = self.session.get(f"{BASE_URL}/api/loans/invalid_loan_id")
        assert resp.status_code == 404
    
    # ============== RECORD REPAYMENT TESTS ==============
    
    def test_record_repayment_partial(self):
        """Test POST /api/loans/{loan_id}/repayment - partial repayment changes status"""
        # First create a loan
        loan = self.test_create_loan_success()
        loan_id = loan["loan_id"]
        
        # Find a treasury account to receive repayment
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        treasury = self.treasury_accounts[0]
        
        # Get current treasury balance AFTER loan was created (loan already deducted)
        treasury_resp = self.session.get(f"{BASE_URL}/api/treasury/{treasury['account_id']}")
        balance_before_repayment = treasury_resp.json().get("balance", 0) if treasury_resp.status_code == 200 else 0
        
        payload = {
            "amount": 300,  # Partial repayment (out of 1000)
            "currency": loan["currency"],
            "treasury_account_id": treasury["account_id"],
            "payment_date": datetime.now().strftime("%Y-%m-%d"),
            "reference": "TEST-REF-001"
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans/{loan_id}/repayment", json=payload)
        assert resp.status_code == 200, f"Record repayment failed: {resp.text}"
        
        data = resp.json()
        assert "repayment_id" in data
        assert data["amount"] == 300
        assert data["loan_status"] == "partially_paid", "Status should change to partially_paid"
        
        # Verify treasury was credited with repayment amount
        treasury_resp = self.session.get(f"{BASE_URL}/api/treasury/{treasury['account_id']}")
        if treasury_resp.status_code == 200:
            new_balance = treasury_resp.json().get("balance", 0)
            # Balance should have increased by repayment amount
            assert new_balance == balance_before_repayment + 300, f"Treasury should be credited. Expected {balance_before_repayment + 300}, got {new_balance}"
    
    def test_record_repayment_full(self):
        """Test recording repayments until loan is fully paid"""
        # Create a small loan for this test
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        treasury = None
        for acc in self.treasury_accounts:
            if acc.get("status") == "active" and acc.get("balance", 0) >= 200:
                treasury = acc
                break
        
        if not treasury:
            pytest.skip("No treasury account with sufficient balance")
        
        # Create small loan
        payload = {
            "borrower_name": f"TEST_FullPay_{uuid.uuid4().hex[:8]}",
            "amount": 100,
            "currency": treasury.get("currency", "USD"),
            "interest_rate": 0,  # No interest for easy calculation
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
            "repayment_mode": "lump_sum",
            "treasury_account_id": treasury["account_id"]
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans", json=payload)
        assert resp.status_code == 200
        loan = resp.json()
        
        # Record full repayment
        repay_payload = {
            "amount": 100,  # Full amount
            "currency": loan["currency"],
            "treasury_account_id": treasury["account_id"],
            "payment_date": datetime.now().strftime("%Y-%m-%d")
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans/{loan['loan_id']}/repayment", json=repay_payload)
        assert resp.status_code == 200
        
        data = resp.json()
        assert data["loan_status"] == "fully_paid", "Status should be fully_paid"
        assert data["new_outstanding"] == 0, "Outstanding should be 0"
    
    def test_record_repayment_different_treasury(self):
        """Test recording repayment to a different treasury account"""
        # Create a loan first
        loan = self.test_create_loan_success()
        
        # Find a different treasury account
        different_treasury = None
        for acc in self.treasury_accounts:
            if acc["account_id"] != self.test_treasury_id and acc.get("status") == "active":
                different_treasury = acc
                break
        
        if not different_treasury:
            pytest.skip("No different treasury account available")
        
        payload = {
            "amount": 50,
            "currency": different_treasury.get("currency", "USD"),
            "treasury_account_id": different_treasury["account_id"],
            "payment_date": datetime.now().strftime("%Y-%m-%d"),
            "reference": "DIFFERENT-TREASURY-REF"
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans/{loan['loan_id']}/repayment", json=payload)
        assert resp.status_code == 200
        
        data = resp.json()
        assert data["treasury_account_id"] == different_treasury["account_id"]
    
    def test_record_repayment_zero_amount(self):
        """Test recording repayment with zero amount fails"""
        loan = self.test_create_loan_success()
        
        payload = {
            "amount": 0,
            "currency": "USD",
            "treasury_account_id": self.treasury_accounts[0]["account_id"]
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans/{loan['loan_id']}/repayment", json=payload)
        assert resp.status_code == 400, "Should reject zero amount"
    
    def test_record_repayment_invalid_treasury(self):
        """Test recording repayment to invalid treasury fails"""
        loan = self.test_create_loan_success()
        
        payload = {
            "amount": 50,
            "currency": "USD",
            "treasury_account_id": "invalid_id"
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans/{loan['loan_id']}/repayment", json=payload)
        assert resp.status_code == 404, "Should reject invalid treasury"
    
    def test_record_repayment_fully_paid_loan(self):
        """Test cannot record repayment on fully paid loan"""
        # Create and fully pay a loan first
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        treasury = None
        for acc in self.treasury_accounts:
            if acc.get("status") == "active" and acc.get("balance", 0) >= 100:
                treasury = acc
                break
        
        if not treasury:
            pytest.skip("No treasury account with sufficient balance")
        
        # Create small loan
        payload = {
            "borrower_name": f"TEST_AlreadyPaid_{uuid.uuid4().hex[:8]}",
            "amount": 50,
            "currency": treasury.get("currency", "USD"),
            "interest_rate": 0,
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
            "treasury_account_id": treasury["account_id"]
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans", json=payload)
        loan = resp.json()
        
        # Pay it off
        self.session.post(f"{BASE_URL}/api/loans/{loan['loan_id']}/repayment", json={
            "amount": 50,
            "currency": loan["currency"],
            "treasury_account_id": treasury["account_id"]
        })
        
        # Try to pay again
        resp = self.session.post(f"{BASE_URL}/api/loans/{loan['loan_id']}/repayment", json={
            "amount": 10,
            "currency": loan["currency"],
            "treasury_account_id": treasury["account_id"]
        })
        assert resp.status_code == 400, "Should reject repayment on fully paid loan"
        assert "fully paid" in resp.json().get("detail", "").lower()
    
    # ============== DELETE LOAN TESTS ==============
    
    def test_delete_loan_no_repayments(self):
        """Test DELETE /api/loans/{loan_id} reverses treasury balance"""
        loan = self.test_create_loan_success()
        
        # Get treasury balance before delete
        treasury_resp = self.session.get(f"{BASE_URL}/api/treasury/{self.test_treasury_id}")
        balance_before = treasury_resp.json().get("balance", 0) if treasury_resp.status_code == 200 else 0
        
        # Delete the loan
        resp = self.session.delete(f"{BASE_URL}/api/loans/{loan['loan_id']}")
        assert resp.status_code == 200
        
        # Verify treasury balance was restored
        treasury_resp = self.session.get(f"{BASE_URL}/api/treasury/{self.test_treasury_id}")
        if treasury_resp.status_code == 200:
            balance_after = treasury_resp.json().get("balance", 0)
            assert balance_after == balance_before + 1000, "Treasury should be credited back"
    
    def test_delete_loan_with_repayments_fails(self):
        """Test DELETE /api/loans/{loan_id} fails if loan has repayments"""
        # Create a loan and record a repayment
        loan = self.test_create_loan_success()
        
        # Record a repayment
        self.session.post(f"{BASE_URL}/api/loans/{loan['loan_id']}/repayment", json={
            "amount": 100,
            "currency": loan["currency"],
            "treasury_account_id": self.treasury_accounts[0]["account_id"]
        })
        
        # Try to delete
        resp = self.session.delete(f"{BASE_URL}/api/loans/{loan['loan_id']}")
        assert resp.status_code == 400, "Should not allow deleting loan with repayments"
        assert "repayments" in resp.json().get("detail", "").lower()
    
    def test_delete_loan_not_found(self):
        """Test DELETE /api/loans/{loan_id} returns 404"""
        resp = self.session.delete(f"{BASE_URL}/api/loans/invalid_loan_id")
        assert resp.status_code == 404
    
    # ============== LOAN SUMMARY REPORT TESTS ==============
    
    def test_get_loans_summary(self):
        """Test GET /api/loans/reports/summary returns aggregated data"""
        # Create a loan first to ensure there's data
        self.test_create_loan_success()
        
        resp = self.session.get(f"{BASE_URL}/api/loans/reports/summary")
        assert resp.status_code == 200
        
        data = resp.json()
        assert "total_loans" in data
        assert "total_disbursed_usd" in data
        assert "total_outstanding_usd" in data
        assert "total_repaid_usd" in data
        assert "total_interest_earned_usd" in data
        assert "status_breakdown" in data
        
        # Verify status breakdown structure
        status = data["status_breakdown"]
        assert "active" in status
        assert "partially_paid" in status
        assert "fully_paid" in status
        assert "overdue" in status
    
    # ============== EDGE CASES ==============
    
    def test_loan_interest_calculation(self):
        """Test that loan interest is calculated correctly"""
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        treasury = None
        for acc in self.treasury_accounts:
            if acc.get("status") == "active" and acc.get("balance", 0) >= 1000:
                treasury = acc
                break
        
        if not treasury:
            pytest.skip("No treasury account with sufficient balance")
        
        # Create loan with known interest rate for 1 year
        loan_date = datetime.now().strftime("%Y-%m-%d")
        due_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")  # 1 year
        
        payload = {
            "borrower_name": f"TEST_Interest_{uuid.uuid4().hex[:8]}",
            "amount": 1000,
            "currency": treasury.get("currency", "USD"),
            "interest_rate": 10,  # 10% annual
            "loan_date": loan_date,
            "due_date": due_date,
            "treasury_account_id": treasury["account_id"]
        }
        
        resp = self.session.post(f"{BASE_URL}/api/loans", json=payload)
        assert resp.status_code == 200
        
        data = resp.json()
        # Interest for 1 year at 10% on 1000 = 100
        # Allow small variance due to day calculation
        assert 95 <= data.get("total_interest", 0) <= 105, f"Interest should be ~100, got {data.get('total_interest')}"
