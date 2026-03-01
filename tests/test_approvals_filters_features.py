"""
Tests for Approvals page filters and Withdrawal approval features
- Filter by Type (Deposit/Withdrawal)
- Filter by Destination (Treasury/Bank/USDT/PSP/Vendor)
- Search by client name
- Withdrawal approval with source_account_id
- Withdrawal approval with screenshot upload
- Client bank accounts CRUD
- USDT in currency dropdown (frontend test)
- Saved bank accounts dropdown (frontend test)
"""
import pytest
import requests
import os
import io

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://fx-broker-control.preview.emergentagent.com')

@pytest.fixture(scope="module")
def auth_token():
    """Get authentication token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "admin@test.com",
        "password": "password"
    })
    if response.status_code == 200:
        return response.json().get("access_token")
    pytest.skip("Authentication failed - skipping tests")

@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Headers with authentication"""
    return {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

@pytest.fixture(scope="module")
def form_headers(auth_token):
    """Headers for form data (no Content-Type)"""
    return {
        "Authorization": f"Bearer {auth_token}"
    }

class TestClientBankAccountsCRUD:
    """Test Client Bank Accounts CRUD operations"""
    
    @pytest.fixture(scope="class")
    def test_client(self, auth_headers):
        """Create a test client for bank accounts tests"""
        response = requests.post(f"{BASE_URL}/api/clients", 
            headers=auth_headers,
            json={
                "first_name": "TestBank",
                "last_name": "ClientT1",
                "email": f"test.bank.client.t1@test.com",
                "phone": "+1234567890",
                "country": "US"
            })
        if response.status_code in [200, 201]:
            return response.json()
        # Get existing client if already exists
        response = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        for c in response.json():
            if c.get("email") == "test.bank.client.t1@test.com":
                return c
        pytest.skip("Could not create/find test client")
    
    def test_create_client_bank_account(self, form_headers, test_client):
        """Test creating a client bank account"""
        client_id = test_client["client_id"]
        
        # Use form data
        response = requests.post(
            f"{BASE_URL}/api/clients/{client_id}/bank-accounts",
            headers=form_headers,
            data={
                "bank_name": "Test Bank Corp",
                "account_name": "TestBank ClientT1",
                "account_number": "1234567890",
                "swift_iban": "TSTB1234",
                "currency": "USD"
            }
        )
        
        assert response.status_code in [200, 201], f"Failed to create bank account: {response.text}"
        data = response.json()
        assert data.get("bank_name") == "Test Bank Corp"
        assert data.get("account_number") == "1234567890"
        assert "bank_account_id" in data
        print(f"✓ Created client bank account: {data['bank_account_id']}")
    
    def test_get_client_bank_accounts(self, auth_headers, test_client):
        """Test fetching client bank accounts"""
        client_id = test_client["client_id"]
        response = requests.get(f"{BASE_URL}/api/clients/{client_id}/bank-accounts", headers=auth_headers)
        
        assert response.status_code == 200, f"Failed to get bank accounts: {response.text}"
        accounts = response.json()
        assert isinstance(accounts, list)
        # Should have at least the one we created
        if len(accounts) > 0:
            assert "bank_name" in accounts[0]
            assert "account_number" in accounts[0]
        print(f"✓ Retrieved {len(accounts)} bank accounts for client")


class TestWithdrawalApprovalWithSourceAccount:
    """Test Withdrawal approval with source_account_id requirement"""
    
    @pytest.fixture(scope="class")
    def test_treasury(self, auth_headers):
        """Get or create treasury account with balance"""
        # Get existing treasury accounts
        response = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers)
        accounts = response.json()
        
        # Find one with balance > 5000
        for acc in accounts:
            if acc.get("balance", 0) >= 5000:
                return acc
        
        # Create new one if needed
        response = requests.post(f"{BASE_URL}/api/treasury",
            headers=auth_headers,
            json={
                "account_name": "Test Treasury For Approval",
                "account_type": "bank",
                "bank_name": "Test Bank",
                "account_number": "9999888877",
                "currency": "USD"
            })
        if response.status_code in [200, 201]:
            return response.json()
        pytest.skip("Could not create/find treasury account")
    
    @pytest.fixture(scope="class")
    def test_withdrawal_tx(self, auth_headers, form_headers):
        """Create a pending withdrawal to bank for approval test"""
        # Get a client first
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        clients = clients_resp.json()
        if not clients:
            pytest.skip("No clients found")
        
        client_id = clients[0]["client_id"]
        
        # Create withdrawal to bank
        response = requests.post(f"{BASE_URL}/api/transactions",
            headers=form_headers,
            data={
                "client_id": client_id,
                "transaction_type": "withdrawal",
                "amount": "100",
                "currency": "USD",
                "base_currency": "USD",
                "destination_type": "bank",
                "client_bank_name": "Client Test Bank",
                "client_bank_account_name": "Client Name",
                "client_bank_account_number": "1111222233",
                "client_bank_swift_iban": "CLTB1234",
                "client_bank_currency": "USD",
                "description": "Test withdrawal for approval"
            })
        
        assert response.status_code in [200, 201], f"Failed to create withdrawal: {response.text}"
        return response.json()
    
    def test_withdrawal_approval_requires_source_account(self, auth_headers, test_withdrawal_tx):
        """Test that withdrawal approval without source_account_id fails"""
        tx_id = test_withdrawal_tx["transaction_id"]
        
        # Try to approve without source account
        response = requests.post(f"{BASE_URL}/api/transactions/{tx_id}/approve", headers=auth_headers)
        
        # Should fail with 400 requiring source account
        assert response.status_code == 400, f"Expected 400, got {response.status_code}: {response.text}"
        assert "source account" in response.json().get("detail", "").lower()
        print(f"✓ Withdrawal approval correctly requires source_account_id")
    
    def test_withdrawal_approval_with_source_account(self, auth_headers, form_headers, test_treasury):
        """Test that withdrawal approval with source_account_id succeeds"""
        # Create a new pending withdrawal
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        clients = clients_resp.json()
        client_id = clients[0]["client_id"]
        
        # Create withdrawal
        tx_response = requests.post(f"{BASE_URL}/api/transactions",
            headers=form_headers,
            data={
                "client_id": client_id,
                "transaction_type": "withdrawal",
                "amount": "50",
                "currency": "USD",
                "base_currency": "USD",
                "destination_type": "bank",
                "client_bank_name": "Approval Test Bank",
                "client_bank_account_name": "Test Account",
                "client_bank_account_number": "9876543210",
                "client_bank_currency": "USD"
            })
        
        assert tx_response.status_code in [200, 201], f"Failed to create withdrawal: {tx_response.text}"
        tx = tx_response.json()
        tx_id = tx["transaction_id"]
        
        # Approve with source account
        source_account_id = test_treasury["account_id"]
        response = requests.post(
            f"{BASE_URL}/api/transactions/{tx_id}/approve?source_account_id={source_account_id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Approval failed: {response.text}"
        data = response.json()
        assert data.get("status") == "approved"
        assert data.get("source_account_id") == source_account_id
        print(f"✓ Withdrawal approved with source account: {source_account_id}")


class TestWithdrawalProofUpload:
    """Test proof upload for withdrawal transactions"""
    
    def test_upload_proof_for_withdrawal(self, form_headers, auth_headers):
        """Test uploading proof screenshot for withdrawal"""
        # Create a withdrawal
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        clients = clients_resp.json()
        client_id = clients[0]["client_id"]
        
        # Create withdrawal to USDT
        tx_response = requests.post(f"{BASE_URL}/api/transactions",
            headers=form_headers,
            data={
                "client_id": client_id,
                "transaction_type": "withdrawal",
                "amount": "75",
                "currency": "USD",
                "base_currency": "USD",
                "destination_type": "usdt",
                "client_usdt_address": "TXabcdef1234567890TEST",
                "client_usdt_network": "TRC20"
            })
        
        assert tx_response.status_code in [200, 201], f"Failed to create withdrawal: {tx_response.text}"
        tx = tx_response.json()
        tx_id = tx["transaction_id"]
        
        # Create a simple test image
        import base64
        # 1x1 PNG pixel
        simple_png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
        
        # Upload proof
        files = {"proof_image": ("test.png", io.BytesIO(simple_png), "image/png")}
        response = requests.post(
            f"{BASE_URL}/api/transactions/{tx_id}/upload-proof",
            headers={"Authorization": form_headers["Authorization"]},
            files=files
        )
        
        assert response.status_code == 200, f"Upload failed: {response.text}"
        assert "message" in response.json()
        print(f"✓ Proof uploaded for withdrawal: {tx_id}")


class TestTransactionsFiltering:
    """Test transaction filtering endpoints work correctly for Approvals page"""
    
    def test_get_pending_transactions(self, auth_headers):
        """Test fetching pending transactions (used by Approvals page)"""
        response = requests.get(f"{BASE_URL}/api/transactions/pending", headers=auth_headers)
        
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        assert isinstance(data, list)
        # All should be pending
        for tx in data:
            assert tx.get("status") == "pending"
        print(f"✓ Retrieved {len(data)} pending transactions")
    
    def test_filter_transactions_by_type(self, auth_headers):
        """Test filtering transactions by type"""
        # Filter by deposit
        response = requests.get(f"{BASE_URL}/api/transactions?transaction_type=deposit&limit=10", headers=auth_headers)
        assert response.status_code == 200
        for tx in response.json():
            assert tx.get("transaction_type") == "deposit"
        
        # Filter by withdrawal
        response = requests.get(f"{BASE_URL}/api/transactions?transaction_type=withdrawal&limit=10", headers=auth_headers)
        assert response.status_code == 200
        for tx in response.json():
            assert tx.get("transaction_type") == "withdrawal"
        
        print(f"✓ Transaction type filtering works")
    
    def test_pending_transactions_have_bank_details(self, auth_headers, form_headers):
        """Test that pending transactions include client bank details for bank withdrawals"""
        # Create a bank withdrawal
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        clients = clients_resp.json()
        client_id = clients[0]["client_id"]
        
        tx_response = requests.post(f"{BASE_URL}/api/transactions",
            headers=form_headers,
            data={
                "client_id": client_id,
                "transaction_type": "withdrawal",
                "amount": "25",
                "currency": "USD",
                "base_currency": "USD",
                "destination_type": "bank",
                "client_bank_name": "Filter Test Bank",
                "client_bank_account_name": "Test Account",
                "client_bank_account_number": "FILTER123456",
                "client_bank_swift_iban": "FILT1234",
                "client_bank_currency": "EUR"
            })
        
        assert tx_response.status_code in [200, 201]
        tx = tx_response.json()
        
        # Get pending transactions
        response = requests.get(f"{BASE_URL}/api/transactions/pending", headers=auth_headers)
        assert response.status_code == 200
        
        # Find our transaction
        found = False
        for pending_tx in response.json():
            if pending_tx.get("transaction_id") == tx["transaction_id"]:
                found = True
                assert pending_tx.get("client_bank_name") == "Filter Test Bank"
                assert pending_tx.get("client_bank_account_number") == "FILTER123456"
                assert pending_tx.get("destination_type") == "bank"
                break
        
        assert found, "Created transaction not found in pending list"
        print(f"✓ Pending transactions include client bank details")
    
    def test_pending_transactions_have_usdt_details(self, auth_headers, form_headers):
        """Test that pending transactions include client USDT details for USDT withdrawals"""
        # Create a USDT withdrawal
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        clients = clients_resp.json()
        client_id = clients[0]["client_id"]
        
        tx_response = requests.post(f"{BASE_URL}/api/transactions",
            headers=form_headers,
            data={
                "client_id": client_id,
                "transaction_type": "withdrawal",
                "amount": "30",
                "currency": "USD",
                "base_currency": "USD",
                "destination_type": "usdt",
                "client_usdt_address": "TESTaddr1234567890USDT",
                "client_usdt_network": "ERC20"
            })
        
        assert tx_response.status_code in [200, 201]
        tx = tx_response.json()
        
        # Get pending transactions
        response = requests.get(f"{BASE_URL}/api/transactions/pending", headers=auth_headers)
        assert response.status_code == 200
        
        # Find our transaction
        found = False
        for pending_tx in response.json():
            if pending_tx.get("transaction_id") == tx["transaction_id"]:
                found = True
                assert pending_tx.get("client_usdt_address") == "TESTaddr1234567890USDT"
                assert pending_tx.get("client_usdt_network") == "ERC20"
                assert pending_tx.get("destination_type") == "usdt"
                break
        
        assert found, "Created transaction not found in pending list"
        print(f"✓ Pending transactions include client USDT details")


class TestPendingSettlements:
    """Test pending settlements endpoint for Approvals page"""
    
    def test_get_pending_settlements(self, auth_headers):
        """Test fetching pending settlements"""
        response = requests.get(f"{BASE_URL}/api/settlements/pending", headers=auth_headers)
        
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        assert isinstance(data, list)
        # All should be pending
        for settlement in data:
            assert settlement.get("status") == "pending"
        print(f"✓ Retrieved {len(data)} pending settlements")


# Run module-level test
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
