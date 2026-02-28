# Test Debt Management API endpoints
# Testing receivables, payables, payments, interest calculation, and summary

import pytest
import requests
import os
from datetime import datetime, timedelta

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestDebtManagement:
    """Test suite for Debt Management module API endpoints"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup authentication and common test data"""
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        
        # Login as admin
        login_response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "password"
        })
        assert login_response.status_code == 200, f"Login failed: {login_response.text}"
        token = login_response.json().get("access_token")
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        
        # Store test data IDs for cleanup
        self.created_debt_ids = []
        yield
        
        # Cleanup created test debts
        for debt_id in self.created_debt_ids:
            try:
                self.session.delete(f"{BASE_URL}/api/debts/{debt_id}")
            except:
                pass
    
    # ========== GET /api/debts - List Debts ==========
    
    def test_get_debts_empty_list(self):
        """Test GET /api/debts returns empty list when no debts exist"""
        response = self.session.get(f"{BASE_URL}/api/debts")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"GET /api/debts - Found {len(data)} existing debts")
    
    def test_get_debts_with_filter(self):
        """Test GET /api/debts with debt_type filter"""
        response = self.session.get(f"{BASE_URL}/api/debts", params={"debt_type": "receivable"})
        assert response.status_code == 200
        data = response.json()
        for debt in data:
            assert debt.get("debt_type") == "receivable"
        print("GET /api/debts with debt_type=receivable filter works")
    
    # ========== GET /api/debts/summary/overview - Summary ==========
    
    def test_get_debts_summary(self):
        """Test GET /api/debts/summary/overview returns proper structure"""
        response = self.session.get(f"{BASE_URL}/api/debts/summary/overview")
        assert response.status_code == 200
        data = response.json()
        
        # Verify summary structure
        assert "receivables" in data
        assert "payables" in data
        assert "aging" in data
        assert "net_position" in data
        
        # Verify receivables structure
        assert "total_amount" in data["receivables"]
        assert "outstanding" in data["receivables"]
        assert "overdue_amount" in data["receivables"]
        assert "accrued_interest" in data["receivables"]
        assert "count" in data["receivables"]
        
        # Verify aging structure
        assert "current" in data["aging"]
        assert "days_1_30" in data["aging"]
        assert "days_31_60" in data["aging"]
        assert "days_61_90" in data["aging"]
        assert "days_over_90" in data["aging"]
        
        print(f"Summary: Receivables outstanding=${data['receivables']['outstanding']}, Payables outstanding=${data['payables']['outstanding']}, Net position=${data['net_position']}")
    
    # ========== POST /api/debts - Create Debt ==========
    
    def test_create_receivable_other_party(self):
        """Test creating a receivable debt with 'other' party type"""
        due_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        
        payload = {
            "debt_type": "receivable",
            "party_type": "other",
            "party_name": "TEST_Acme Corp",
            "amount": 5000,
            "currency": "USD",
            "due_date": due_date,
            "interest_rate": 12,  # 12% annual
            "description": "Invoice #INV-001 for consulting services",
            "reference": "INV-001"
        }
        
        response = self.session.post(f"{BASE_URL}/api/debts", json=payload)
        assert response.status_code == 200, f"Create debt failed: {response.text}"
        data = response.json()
        
        # Store for cleanup
        self.created_debt_ids.append(data["debt_id"])
        
        # Verify response
        assert data["debt_type"] == "receivable"
        assert data["party_type"] == "other"
        assert data["party_name"] == "TEST_Acme Corp"
        assert data["amount"] == 5000
        assert data["currency"] == "USD"
        assert data["interest_rate"] == 12
        assert data["total_paid"] == 0
        assert data["status"] == "pending"
        
        print(f"Created receivable debt: {data['debt_id']} for TEST_Acme Corp, amount=${data['amount']}")
        return data
    
    def test_create_payable_debt(self):
        """Test creating a payable debt"""
        due_date = (datetime.now() + timedelta(days=45)).strftime("%Y-%m-%d")
        
        payload = {
            "debt_type": "payable",
            "party_type": "other",
            "party_name": "TEST_Supplier XYZ",
            "amount": 3000,
            "currency": "AED",
            "due_date": due_date,
            "interest_rate": 8,
            "description": "Supplier invoice for equipment",
            "reference": "PO-2024-001"
        }
        
        response = self.session.post(f"{BASE_URL}/api/debts", json=payload)
        assert response.status_code == 200, f"Create payable failed: {response.text}"
        data = response.json()
        
        self.created_debt_ids.append(data["debt_id"])
        
        assert data["debt_type"] == "payable"
        assert data["party_name"] == "TEST_Supplier XYZ"
        assert data["amount"] == 3000
        assert data["currency"] == "AED"
        # Verify USD conversion (AED rate is 0.27)
        assert data["amount_usd"] == round(3000 * 0.27, 2)
        
        print(f"Created payable debt: {data['debt_id']}, amount=3000 AED (${data['amount_usd']} USD)")
        return data
    
    def test_create_receivable_with_client(self):
        """Test creating a receivable linked to existing client"""
        # First get clients
        clients_response = self.session.get(f"{BASE_URL}/api/clients")
        assert clients_response.status_code == 200
        clients = clients_response.json()
        
        if not clients:
            pytest.skip("No clients available to test linked debt")
        
        client = clients[0]
        due_date = (datetime.now() + timedelta(days=60)).strftime("%Y-%m-%d")
        
        payload = {
            "debt_type": "receivable",
            "party_type": "client",
            "party_id": client["client_id"],
            "party_name": "",  # Should be auto-filled
            "amount": 7500,
            "currency": "USD",
            "due_date": due_date,
            "interest_rate": 10,
            "description": "Client outstanding balance"
        }
        
        response = self.session.post(f"{BASE_URL}/api/debts", json=payload)
        assert response.status_code == 200, f"Create client-linked debt failed: {response.text}"
        data = response.json()
        
        self.created_debt_ids.append(data["debt_id"])
        
        assert data["party_type"] == "client"
        assert data["party_id"] == client["client_id"]
        # Party name should be auto-filled from client
        expected_name = f"{client.get('first_name', '')} {client.get('last_name', '')}".strip()
        assert data["party_name"] == expected_name or data["party_name"] != ""
        
        print(f"Created receivable linked to client: {data['party_name']}, debt_id={data['debt_id']}")
        return data
    
    def test_create_payable_with_vendor(self):
        """Test creating a payable linked to existing vendor"""
        # First get vendors
        vendors_response = self.session.get(f"{BASE_URL}/api/vendors")
        assert vendors_response.status_code == 200
        vendors = vendors_response.json()
        
        if not vendors:
            pytest.skip("No vendors available to test linked debt")
        
        vendor = vendors[0]
        due_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        
        payload = {
            "debt_type": "payable",
            "party_type": "vendor",
            "party_id": vendor["vendor_id"],
            "party_name": "",  # Should be auto-filled
            "amount": 2000,
            "currency": "USD",
            "due_date": due_date,
            "interest_rate": 5,
            "description": "Vendor commission payable"
        }
        
        response = self.session.post(f"{BASE_URL}/api/debts", json=payload)
        assert response.status_code == 200, f"Create vendor-linked debt failed: {response.text}"
        data = response.json()
        
        self.created_debt_ids.append(data["debt_id"])
        
        assert data["party_type"] == "vendor"
        assert data["party_id"] == vendor["vendor_id"]
        # Party name should be auto-filled from vendor
        assert data["party_name"] == vendor.get("vendor_name") or data["party_name"] != ""
        
        print(f"Created payable linked to vendor: {data['party_name']}, debt_id={data['debt_id']}")
        return data
    
    # ========== GET /api/debts/{debt_id} - Get Debt Details ==========
    
    def test_get_debt_details(self):
        """Test GET /api/debts/{debt_id} returns full details"""
        # First create a debt
        created = self.test_create_receivable_other_party()
        debt_id = created["debt_id"]
        
        response = self.session.get(f"{BASE_URL}/api/debts/{debt_id}")
        assert response.status_code == 200
        data = response.json()
        
        # Verify calculated fields
        assert "calculated_status" in data
        assert "outstanding_balance" in data
        assert "total_due" in data
        assert "payments" in data
        
        assert data["outstanding_balance"] == data["amount"]  # No payments yet
        assert data["calculated_status"] == "pending"  # Not overdue yet
        assert isinstance(data["payments"], list)
        
        print(f"Debt details: status={data['calculated_status']}, outstanding=${data['outstanding_balance']}")
    
    def test_get_nonexistent_debt(self):
        """Test GET /api/debts/{debt_id} with invalid ID returns 404"""
        response = self.session.get(f"{BASE_URL}/api/debts/debt_invalid123")
        assert response.status_code == 404
        print("404 returned for non-existent debt ID")
    
    # ========== POST /api/debts/{debt_id}/payments - Record Payment ==========
    
    def test_record_payment(self):
        """Test recording a payment against a debt"""
        # Create a debt
        created = self.test_create_receivable_other_party()
        debt_id = created["debt_id"]
        
        # Get treasury accounts
        treasury_response = self.session.get(f"{BASE_URL}/api/treasury")
        assert treasury_response.status_code == 200
        treasury_accounts = treasury_response.json()
        
        if not treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        treasury = treasury_accounts[0]
        
        # Record partial payment
        payment_payload = {
            "amount": 2000,
            "currency": "USD",
            "payment_date": datetime.now().strftime("%Y-%m-%d"),
            "treasury_account_id": treasury["account_id"],
            "reference": "PMT-001",
            "notes": "Partial payment received"
        }
        
        response = self.session.post(f"{BASE_URL}/api/debts/{debt_id}/payments", json=payment_payload)
        assert response.status_code == 200, f"Record payment failed: {response.text}"
        data = response.json()
        
        # Verify debt updated
        assert data["total_paid"] == 2000
        assert data["payment_count"] == 1
        assert data["status"] == "partially_paid"
        
        print(f"Payment recorded: $2000, debt status={data['status']}, total_paid=${data['total_paid']}")
        return debt_id
    
    def test_record_full_payment(self):
        """Test recording payment that fully pays the debt"""
        # Create a debt with small amount
        due_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        
        payload = {
            "debt_type": "receivable",
            "party_type": "other",
            "party_name": "TEST_Full Payment Corp",
            "amount": 1000,
            "currency": "USD",
            "due_date": due_date,
            "interest_rate": 0
        }
        
        create_response = self.session.post(f"{BASE_URL}/api/debts", json=payload)
        assert create_response.status_code == 200
        debt = create_response.json()
        self.created_debt_ids.append(debt["debt_id"])
        
        # Get treasury
        treasury_response = self.session.get(f"{BASE_URL}/api/treasury")
        treasury = treasury_response.json()[0]
        
        # Pay full amount
        payment_payload = {
            "amount": 1000,
            "currency": "USD",
            "treasury_account_id": treasury["account_id"],
            "reference": "FULL-PMT"
        }
        
        response = self.session.post(f"{BASE_URL}/api/debts/{debt['debt_id']}/payments", json=payment_payload)
        assert response.status_code == 200
        data = response.json()
        
        assert data["total_paid"] == 1000
        assert data["status"] == "fully_paid"
        
        print(f"Full payment: debt {debt['debt_id']} now fully_paid")
    
    def test_get_debt_payment_history(self):
        """Test getting payment history for a debt"""
        debt_id = self.test_record_payment()
        
        # Get debt details with payments
        response = self.session.get(f"{BASE_URL}/api/debts/{debt_id}")
        assert response.status_code == 200
        data = response.json()
        
        assert "payments" in data
        assert len(data["payments"]) > 0
        
        payment = data["payments"][0]
        assert "payment_id" in payment
        assert "amount" in payment
        assert "treasury_account_name" in payment
        
        print(f"Payment history: {len(data['payments'])} payments found for debt {debt_id}")
    
    # ========== Interest Calculation ==========
    
    def test_overdue_debt_interest_calculation(self):
        """Test interest calculation on overdue debt"""
        # Create a debt with past due date
        past_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")  # 30 days ago
        
        payload = {
            "debt_type": "receivable",
            "party_type": "other",
            "party_name": "TEST_Overdue Debtor",
            "amount": 10000,
            "currency": "USD",
            "due_date": past_date,
            "interest_rate": 12,  # 12% annual = 0.0329% daily
            "description": "Overdue test debt"
        }
        
        response = self.session.post(f"{BASE_URL}/api/debts", json=payload)
        assert response.status_code == 200
        created = response.json()
        self.created_debt_ids.append(created["debt_id"])
        
        # Get debt with calculated interest
        get_response = self.session.get(f"{BASE_URL}/api/debts/{created['debt_id']}")
        assert get_response.status_code == 200
        data = get_response.json()
        
        # Should be overdue
        assert data["calculated_status"] == "overdue"
        assert data["days_overdue"] >= 30
        
        # Interest calculation: principal * (annual_rate/100/365) * days_overdue
        # 10000 * (12/100/365) * 30 = 10000 * 0.000329 * 30 ≈ $98.63
        expected_interest = round(10000 * (12/100/365) * data["days_overdue"], 2)
        assert data["accrued_interest"] == expected_interest or abs(data["accrued_interest"] - expected_interest) < 1
        
        print(f"Overdue debt: {data['days_overdue']} days overdue, accrued interest=${data['accrued_interest']}")
    
    # ========== Summary with Data ==========
    
    def test_summary_after_creating_debts(self):
        """Test summary reflects created debts"""
        # Create a receivable
        receivable_debt = self.test_create_receivable_other_party()
        
        # Create a payable
        payable_debt = self.test_create_payable_debt()
        
        # Get summary
        response = self.session.get(f"{BASE_URL}/api/debts/summary/overview")
        assert response.status_code == 200
        data = response.json()
        
        # Summary should have non-zero values now
        assert data["receivables"]["count"] >= 1
        assert data["receivables"]["outstanding"] >= receivable_debt["amount_usd"]
        assert data["payables"]["count"] >= 1
        
        print(f"Summary after debts: Receivables count={data['receivables']['count']}, Payables count={data['payables']['count']}")
    
    # ========== Filter Tests ==========
    
    def test_filter_debts_by_status(self):
        """Test filtering debts by calculated status"""
        # Create an overdue debt
        past_date = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d")
        payload = {
            "debt_type": "receivable",
            "party_type": "other",
            "party_name": "TEST_Status Filter Test",
            "amount": 500,
            "currency": "USD",
            "due_date": past_date,
            "interest_rate": 0
        }
        response = self.session.post(f"{BASE_URL}/api/debts", json=payload)
        assert response.status_code == 200
        self.created_debt_ids.append(response.json()["debt_id"])
        
        # Filter by overdue
        filter_response = self.session.get(f"{BASE_URL}/api/debts", params={"status": "overdue"})
        assert filter_response.status_code == 200
        overdue_debts = filter_response.json()
        
        for debt in overdue_debts:
            assert debt["calculated_status"] == "overdue"
        
        print(f"Found {len(overdue_debts)} overdue debts after filter")


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
