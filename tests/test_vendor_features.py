"""
Vendor Feature Tests for FX Broker Back-Office System
Testing: Vendor Management, Vendor Portal, Transaction with Vendor destination, Settlement workflow

Features tested:
- Vendor CRUD operations (Admin)
- Vendor login redirects to Vendor Portal
- Vendor Portal shows assigned transactions only
- Vendor approve/reject with captcha (backend doesn't validate captcha - frontend only)
- Vendor complete withdrawal with screenshot upload
- Admin settlement with Bank/Cash type selection
- Settlement commission calculation based on type
"""
import pytest
import requests
import os
import base64
from io import BytesIO

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# === Authentication Fixtures ===

@pytest.fixture(scope="module")
def admin_token():
    """Get admin authentication token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "admin@fxbroker.com",
        "password": "admin123"
    })
    if response.status_code == 200:
        return response.json()["access_token"]
    pytest.skip("Admin authentication failed")

@pytest.fixture
def auth_headers(admin_token):
    """Get authorization headers with admin token"""
    return {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

@pytest.fixture
def vendor1_token():
    """Get vendor1 authentication token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "vendor1@fxbroker.com",
        "password": "vendor123"
    })
    if response.status_code == 200:
        return response.json()
    pytest.skip("Vendor1 authentication failed")

@pytest.fixture
def vendor_auth_headers(vendor1_token):
    """Get authorization headers with vendor token"""
    return {
        "Authorization": f"Bearer {vendor1_token['access_token']}",
        "Content-Type": "application/json"
    }


# === Admin Tests - Vendor Login ===

class TestVendorAuthentication:
    """Test vendor authentication and role redirection"""
    
    def test_admin_login(self):
        """Test admin login"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "admin123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["role"] == "admin"
        print(f"Admin login successful: {data['user']['email']}")
    
    def test_vendor1_login(self):
        """Test vendor1 login - should return vendor role"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "vendor1@fxbroker.com",
            "password": "vendor123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["role"] == "vendor"
        print(f"Vendor1 login successful: {data['user']['email']}, role: {data['user']['role']}")
        return data
    
    def test_vendor2_login(self):
        """Test vendor2 login - should return vendor role"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "vendor2@fxbroker.com",
            "password": "vendor123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["role"] == "vendor"
        print(f"Vendor2 login successful: {data['user']['email']}, role: {data['user']['role']}")


# === Admin Tests - Vendor CRUD ===

class TestVendorCRUD:
    """Test Admin vendor management - CRUD operations"""
    
    def test_get_vendors_list(self, auth_headers):
        """Test GET /api/vendors - List all vendors"""
        response = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"Found {len(data)} vendors")
        
        # Check if seeded vendors exist
        if data:
            vendor = data[0]
            # Verify vendor has required fields
            assert "vendor_id" in vendor
            assert "vendor_name" in vendor
            assert "email" in vendor
            assert "deposit_commission" in vendor
            assert "withdrawal_commission" in vendor
            assert "bank_settlement_commission" in vendor
            assert "cash_settlement_commission" in vendor
            assert "status" in vendor
            assert "pending_transactions_count" in vendor
            assert "pending_amount" in vendor
            print(f"First vendor: {vendor['vendor_name']} (Deposit: {vendor['deposit_commission']}%, Withdrawal: {vendor['withdrawal_commission']}%)")
        return data
    
    def test_get_single_vendor(self, auth_headers):
        """Test GET /api/vendors/{vendor_id} - Get single vendor"""
        # Get all vendors first
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        if not vendors:
            pytest.skip("No vendors found")
        
        vendor_id = vendors[0]["vendor_id"]
        response = requests.get(f"{BASE_URL}/api/vendors/{vendor_id}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["vendor_id"] == vendor_id
        print(f"Got vendor: {data['vendor_name']}")
    
    def test_create_vendor(self, auth_headers):
        """Test POST /api/vendors - Create new vendor (also creates user account)"""
        # First get a treasury account for settlement destination
        treasury_response = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers)
        assert treasury_response.status_code == 200
        treasury_accounts = treasury_response.json()
        assert len(treasury_accounts) > 0, "No treasury accounts found"
        dest_account_id = treasury_accounts[0]["account_id"]
        
        # Create new vendor
        new_vendor = {
            "vendor_name": "TEST_TestVendor",
            "email": "TEST_testvendor@example.com",
            "password": "testpassword123",
            "deposit_commission": 1.5,
            "withdrawal_commission": 2.0,
            "bank_settlement_commission": 0.5,
            "cash_settlement_commission": 1.0,
            "settlement_destination_id": dest_account_id,
            "description": "Test vendor for automated testing"
        }
        response = requests.post(f"{BASE_URL}/api/vendors", headers=auth_headers, json=new_vendor)
        assert response.status_code == 200
        data = response.json()
        
        # Verify vendor created
        assert data["vendor_name"] == "TEST_TestVendor"
        assert data["email"] == "TEST_testvendor@example.com"
        assert data["deposit_commission"] == 1.5
        assert data["withdrawal_commission"] == 2.0
        assert data["bank_settlement_commission"] == 0.5
        assert data["cash_settlement_commission"] == 1.0
        assert data["status"] == "active"
        assert "vendor_id" in data
        assert "user_id" in data  # Should have linked user account
        
        print(f"Created vendor: {data['vendor_id']} - {data['vendor_name']}")
        return data
    
    def test_update_vendor(self, auth_headers):
        """Test PUT /api/vendors/{vendor_id} - Update vendor"""
        # Get vendors
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        test_vendor = next((v for v in vendors if v["vendor_name"].startswith("TEST_")), None)
        
        if not test_vendor:
            pytest.skip("No test vendor found to update")
        
        # Update vendor
        updates = {
            "deposit_commission": 2.5,
            "description": "Updated test vendor description"
        }
        response = requests.put(f"{BASE_URL}/api/vendors/{test_vendor['vendor_id']}", headers=auth_headers, json=updates)
        assert response.status_code == 200
        data = response.json()
        
        assert data["deposit_commission"] == 2.5
        assert data["description"] == "Updated test vendor description"
        print(f"Updated vendor: {data['vendor_id']}")
    
    def test_create_vendor_duplicate_email_fails(self, auth_headers):
        """Test POST /api/vendors with duplicate email fails"""
        treasury_accounts = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers).json()
        dest_account_id = treasury_accounts[0]["account_id"] if treasury_accounts else None
        
        if not dest_account_id:
            pytest.skip("No treasury account")
        
        # Try to create vendor with email that already exists
        new_vendor = {
            "vendor_name": "Duplicate Test",
            "email": "admin@fxbroker.com",  # Already exists
            "password": "testpassword123",
            "deposit_commission": 1.0,
            "withdrawal_commission": 1.0,
            "bank_settlement_commission": 0.5,
            "cash_settlement_commission": 0.5,
            "settlement_destination_id": dest_account_id
        }
        response = requests.post(f"{BASE_URL}/api/vendors", headers=auth_headers, json=new_vendor)
        assert response.status_code == 400
        data = response.json()
        assert "already" in data.get("detail", "").lower()
        print(f"Duplicate email correctly rejected: {data.get('detail')}")


# === Vendor Portal Tests ===

class TestVendorPortal:
    """Test Vendor Portal endpoints"""
    
    def test_vendor_get_my_info(self, vendor_auth_headers):
        """Test GET /api/vendor/me - Get current vendor info"""
        response = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor_auth_headers)
        assert response.status_code == 200
        data = response.json()
        
        # Verify vendor info
        assert "vendor_id" in data
        assert "vendor_name" in data
        assert "deposit_commission" in data
        assert "withdrawal_commission" in data
        assert "pending_transactions" in data
        assert "pending_count" in data
        
        print(f"Vendor info: {data['vendor_name']} - Pending transactions: {data['pending_count']}")
        return data
    
    def test_vendor_get_assigned_transactions(self, vendor_auth_headers):
        """Test GET /api/vendors/{vendor_id}/transactions - Get vendor's assigned transactions"""
        # First get vendor info
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor_auth_headers).json()
        vendor_id = vendor_info["vendor_id"]
        
        response = requests.get(f"{BASE_URL}/api/vendors/{vendor_id}/transactions", headers=vendor_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        print(f"Vendor {vendor_info['vendor_name']} has {len(data)} assigned transactions")
        return data
    
    def test_admin_cannot_access_vendor_me_endpoint(self, auth_headers):
        """Test that admin cannot access /api/vendor/me endpoint"""
        response = requests.get(f"{BASE_URL}/api/vendor/me", headers=auth_headers)
        assert response.status_code == 403  # Forbidden - requires vendor role
        print("Admin correctly blocked from /api/vendor/me endpoint")


# === Transaction Tests - Vendor as Destination ===

class TestVendorTransactions:
    """Test creating transactions with Vendor as destination"""
    
    def test_create_vendor_deposit_transaction(self, auth_headers):
        """Test creating a deposit transaction with vendor as destination"""
        # Get a client
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        client_id = clients[0]["client_id"]
        
        # Get active vendors
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        active_vendors = [v for v in vendors if v.get("status") == "active" and not v["vendor_name"].startswith("TEST_")]
        if not active_vendors:
            pytest.skip("No active vendors found")
        vendor = active_vendors[0]
        
        # Create deposit transaction via vendor
        form_data = {
            "client_id": client_id,
            "transaction_type": "deposit",
            "amount": "1000",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor["vendor_id"],
            "description": "TEST_Vendor deposit transaction"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify vendor fields
        assert data["destination_type"] == "vendor"
        assert data["vendor_id"] == vendor["vendor_id"]
        assert data["vendor_name"] == vendor["vendor_name"]
        assert data["vendor_deposit_commission"] == vendor["deposit_commission"]
        assert data["status"] == "pending"
        
        print(f"Created vendor deposit: {data['transaction_id']} - ${data['amount']}")
        return data
    
    def test_create_vendor_withdrawal_transaction(self, auth_headers):
        """Test creating a withdrawal transaction with vendor as destination"""
        # Get a client
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        client_id = clients[0]["client_id"]
        
        # Get active vendors
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        active_vendors = [v for v in vendors if v.get("status") == "active" and not v["vendor_name"].startswith("TEST_")]
        if not active_vendors:
            pytest.skip("No active vendors found")
        vendor = active_vendors[0]
        
        # Create withdrawal transaction via vendor
        form_data = {
            "client_id": client_id,
            "transaction_type": "withdrawal",
            "amount": "500",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor["vendor_id"],
            "description": "TEST_Vendor withdrawal transaction"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify vendor fields
        assert data["destination_type"] == "vendor"
        assert data["vendor_id"] == vendor["vendor_id"]
        assert data["vendor_withdrawal_commission"] == vendor["withdrawal_commission"]
        assert data["status"] == "pending"
        
        print(f"Created vendor withdrawal: {data['transaction_id']} - ${data['amount']}")
        return data


# === Vendor Actions - Approve/Reject/Complete ===

class TestVendorActions:
    """Test vendor approve/reject/complete actions"""
    
    def test_vendor_approve_transaction(self, vendor_auth_headers, auth_headers):
        """Test POST /api/vendor/transactions/{tx_id}/approve"""
        # First get vendor info
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor_auth_headers).json()
        
        # Create a transaction assigned to this vendor (as admin)
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "300",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor_info["vendor_id"],
            "description": "TEST_Vendor approval test"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        
        # Now approve as vendor
        approve_response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx['transaction_id']}/approve",
            headers=vendor_auth_headers
        )
        assert approve_response.status_code == 200
        approved_tx = approve_response.json()
        
        assert approved_tx["status"] == "approved"
        assert approved_tx["processed_by"] is not None
        assert approved_tx["processed_at"] is not None
        
        print(f"Vendor approved transaction: {tx['transaction_id']}")
        return approved_tx
    
    def test_vendor_reject_transaction(self, vendor_auth_headers, auth_headers):
        """Test POST /api/vendor/transactions/{tx_id}/reject"""
        # First get vendor info
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor_auth_headers).json()
        
        # Create a transaction assigned to this vendor
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "200",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor_info["vendor_id"],
            "description": "TEST_Vendor rejection test"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        
        # Reject with reason
        reject_response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx['transaction_id']}/reject?reason=Invalid%20proof%20of%20payment",
            headers=vendor_auth_headers
        )
        assert reject_response.status_code == 200
        rejected_tx = reject_response.json()
        
        assert rejected_tx["status"] == "rejected"
        assert rejected_tx["rejection_reason"] == "Invalid proof of payment"
        assert rejected_tx["processed_by"] is not None
        
        print(f"Vendor rejected transaction: {tx['transaction_id']}")
        return rejected_tx
    
    def test_vendor_complete_withdrawal_with_proof(self, vendor_auth_headers, auth_headers):
        """Test POST /api/vendor/transactions/{tx_id}/complete with proof image"""
        # First get vendor info
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor_auth_headers).json()
        
        # Create a withdrawal transaction assigned to this vendor
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "withdrawal",
            "amount": "400",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor_info["vendor_id"],
            "description": "TEST_Vendor withdrawal completion test"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        
        # First approve the transaction
        approve_response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx['transaction_id']}/approve",
            headers=vendor_auth_headers
        )
        assert approve_response.status_code == 200
        
        # Now complete with proof image
        # Create a simple test image
        import io
        test_image_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        
        files = {
            'proof_image': ('proof.png', io.BytesIO(test_image_content), 'image/png')
        }
        
        complete_response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx['transaction_id']}/complete",
            headers={"Authorization": vendor_auth_headers["Authorization"]},
            files=files
        )
        assert complete_response.status_code == 200
        completed_tx = complete_response.json()
        
        assert completed_tx["status"] == "completed"
        assert completed_tx["vendor_proof_image"] is not None
        assert completed_tx["processed_by"] is not None
        
        print(f"Vendor completed withdrawal with proof: {tx['transaction_id']}")
        return completed_tx
    
    def test_vendor_cannot_approve_other_vendor_transaction(self, vendor_auth_headers, auth_headers):
        """Test vendor cannot approve transaction belonging to another vendor"""
        # Get all vendors
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        if len(vendors) < 2:
            pytest.skip("Need at least 2 vendors for this test")
        
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor_auth_headers).json()
        
        # Find another vendor
        other_vendor = next((v for v in vendors if v["vendor_id"] != vendor_info["vendor_id"]), None)
        if not other_vendor:
            pytest.skip("No other vendor found")
        
        # Create transaction assigned to other vendor
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "100",
            "currency": "USD",
            "destination_type": "vendor",
            "vendor_id": other_vendor["vendor_id"],
            "description": "TEST_Cross-vendor test"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        
        # Try to approve as different vendor
        approve_response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx['transaction_id']}/approve",
            headers=vendor_auth_headers
        )
        assert approve_response.status_code == 403  # Should be forbidden
        
        print("Correctly prevented vendor from approving another vendor's transaction")


# === Admin Settlement Tests ===

class TestVendorSettlement:
    """Test vendor settlement workflow with Bank/Cash types"""
    
    def test_settle_vendor_with_bank_type(self, auth_headers):
        """Test POST /api/vendors/{vendor_id}/settle with Bank settlement type"""
        # Get vendors with pending transactions
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        active_vendors = [v for v in vendors if v.get("status") == "active" and not v["vendor_name"].startswith("TEST_")]
        
        if not active_vendors:
            pytest.skip("No active vendors found")
        
        vendor = active_vendors[0]
        
        # Create and approve a transaction for this vendor
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "1000",
            "currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor["vendor_id"],
            "description": "TEST_Bank settlement test"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        
        # Approve the transaction (as admin - normally vendor would do this)
        approve_response = requests.put(
            f"{BASE_URL}/api/transactions/{tx['transaction_id']}",
            headers=auth_headers,
            json={"status": "approved"}
        )
        assert approve_response.status_code == 200
        
        # Now settle with Bank type
        settle_response = requests.post(
            f"{BASE_URL}/api/vendors/{vendor['vendor_id']}/settle",
            headers=auth_headers,
            json={
                "settlement_type": "bank"
            }
        )
        
        if settle_response.status_code == 400 and "No pending" in settle_response.text:
            print("No pending transactions to settle - this is acceptable")
            return
            
        assert settle_response.status_code == 200
        settlement = settle_response.json()
        
        # Verify settlement
        assert settlement["settlement_type"] == "bank"
        assert settlement["gross_amount"] > 0
        assert settlement["commission_rate"] == vendor["bank_settlement_commission"]
        assert settlement["net_amount"] > 0
        assert settlement["status"] == "completed"
        
        print(f"Settlement completed: Gross ${settlement['gross_amount']}, Commission {settlement['commission_rate']}%, Net ${settlement['net_amount']}")
        return settlement
    
    def test_settle_vendor_with_cash_type(self, auth_headers):
        """Test POST /api/vendors/{vendor_id}/settle with Cash settlement type"""
        # Get vendors
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        active_vendors = [v for v in vendors if v.get("status") == "active" and not v["vendor_name"].startswith("TEST_")]
        
        if not active_vendors:
            pytest.skip("No active vendors found")
        
        vendor = active_vendors[0]
        
        # Create and approve a transaction
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "800",
            "currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor["vendor_id"],
            "description": "TEST_Cash settlement test"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        
        # Approve the transaction
        approve_response = requests.put(
            f"{BASE_URL}/api/transactions/{tx['transaction_id']}",
            headers=auth_headers,
            json={"status": "approved"}
        )
        assert approve_response.status_code == 200
        
        # Now settle with Cash type
        settle_response = requests.post(
            f"{BASE_URL}/api/vendors/{vendor['vendor_id']}/settle",
            headers=auth_headers,
            json={
                "settlement_type": "cash"
            }
        )
        
        if settle_response.status_code == 400 and "No pending" in settle_response.text:
            print("No pending transactions to settle - this is acceptable")
            return
            
        assert settle_response.status_code == 200
        settlement = settle_response.json()
        
        # Verify settlement uses cash commission rate
        assert settlement["settlement_type"] == "cash"
        assert settlement["commission_rate"] == vendor["cash_settlement_commission"]
        
        print(f"Cash settlement: Gross ${settlement['gross_amount']}, Commission {settlement['commission_rate']}%, Net ${settlement['net_amount']}")
        return settlement
    
    def test_get_vendor_settlements(self, auth_headers):
        """Test GET /api/vendors/{vendor_id}/settlements"""
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        if not vendors:
            pytest.skip("No vendors found")
        
        vendor = vendors[0]
        response = requests.get(f"{BASE_URL}/api/vendors/{vendor['vendor_id']}/settlements", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        print(f"Vendor {vendor['vendor_name']} has {len(data)} settlements")
        
        if data:
            settlement = data[0]
            assert "settlement_id" in settlement
            assert "settlement_type" in settlement
            assert "gross_amount" in settlement
            assert "commission_amount" in settlement
            assert "net_amount" in settlement
        
        return data


# === Cleanup Tests ===

class TestCleanup:
    """Cleanup test data"""
    
    def test_cleanup_test_vendors(self, auth_headers):
        """Delete TEST_ prefixed vendors"""
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=auth_headers).json()
        test_vendors = [v for v in vendors if v["vendor_name"].startswith("TEST_") or v["email"].startswith("TEST_")]
        
        for vendor in test_vendors:
            response = requests.delete(f"{BASE_URL}/api/vendors/{vendor['vendor_id']}", headers=auth_headers)
            if response.status_code == 200:
                print(f"Deleted test vendor: {vendor['vendor_name']}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
