"""
Tests for Deposit Approval with Screenshot Upload feature
- Deposit approval requires screenshot upload (like withdrawals)
- upload-proof endpoint works for both deposits and withdrawals
- Accountant proof image shows in Transactions page
"""
import pytest
import requests
import os
import io

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
ACCOUNTANT_EMAIL = "accountant@fxbroker.com"
ACCOUNTANT_PASSWORD = "password"
ADMIN_EMAIL = "admin@fxbroker.com"
ADMIN_PASSWORD = "password"


@pytest.fixture(scope="module")
def admin_token():
    """Get admin auth token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD
    })
    if response.status_code != 200:
        pytest.skip(f"Admin login failed: {response.text}")
    return response.json().get("access_token")


@pytest.fixture(scope="module")
def accountant_token(admin_token):
    """Get accountant auth token - create if doesn't exist"""
    # Try login first
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": ACCOUNTANT_EMAIL,
        "password": ACCOUNTANT_PASSWORD
    })
    if response.status_code == 200:
        return response.json().get("access_token")
    
    # Create accountant user if login fails
    headers = {"Authorization": f"Bearer {admin_token}"}
    create_resp = requests.post(
        f"{BASE_URL}/api/users",
        headers=headers,
        json={
            "email": ACCOUNTANT_EMAIL,
            "password": ACCOUNTANT_PASSWORD,
            "name": "Test Accountant",
            "role": "accountant"
        }
    )
    
    # Login again
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": ACCOUNTANT_EMAIL,
        "password": ACCOUNTANT_PASSWORD
    })
    if response.status_code != 200:
        pytest.skip(f"Accountant login failed after creation: {response.text}")
    return response.json().get("access_token")


@pytest.fixture(scope="module")
def test_client_id(admin_token):
    """Get or create a test client"""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Get existing clients
    response = requests.get(f"{BASE_URL}/api/clients", headers=headers)
    if response.status_code == 200:
        clients = response.json()
        if clients:
            return clients[0]["client_id"]
    
    # Create test client if none exist
    create_resp = requests.post(
        f"{BASE_URL}/api/clients",
        headers=headers,
        json={
            "first_name": "TEST",
            "last_name": "DepositClient",
            "email": "test_deposit_approval@example.com"
        }
    )
    if create_resp.status_code in [200, 201]:
        return create_resp.json()["client_id"]
    
    pytest.skip("Cannot create test client")


@pytest.fixture(scope="module")
def test_treasury_id(admin_token):
    """Get or create a test treasury account"""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Get existing treasury accounts
    response = requests.get(f"{BASE_URL}/api/treasury", headers=headers)
    if response.status_code == 200:
        accounts = response.json()
        if accounts:
            return accounts[0]["account_id"]
    
    # Create test treasury if none exist
    create_resp = requests.post(
        f"{BASE_URL}/api/treasury",
        headers=headers,
        json={
            "account_name": "TEST_DepositApprovalTreasury",
            "account_type": "bank",
            "bank_name": "Test Bank",
            "currency": "USD"
        }
    )
    if create_resp.status_code in [200, 201]:
        return create_resp.json()["account_id"]
    
    pytest.skip("Cannot create test treasury")


def create_test_transaction(headers, client_id, treasury_id, transaction_type, amount, reference):
    """Helper function to create transaction using Form data"""
    data = {
        "client_id": client_id,
        "transaction_type": transaction_type,
        "amount": amount,
        "currency": "USD",
        "destination_type": "treasury",
        "destination_account_id": treasury_id,
        "reference": reference
    }
    
    response = requests.post(
        f"{BASE_URL}/api/transactions",
        headers=headers,
        data=data  # Use data for form submission
    )
    return response


class TestDepositApproval:
    """Tests for deposit approval with screenshot requirement"""
    
    def test_upload_proof_endpoint_works_for_deposits(self, admin_token, test_client_id, test_treasury_id):
        """Test that upload-proof endpoint accepts deposit transactions"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create a pending deposit transaction using Form data
        tx_response = create_test_transaction(
            headers, test_client_id, test_treasury_id, 
            "deposit", 1000, "TEST_DepositProof001"
        )
        assert tx_response.status_code in [200, 201], f"Failed to create transaction: {tx_response.text}"
        
        transaction = tx_response.json()
        transaction_id = transaction["transaction_id"]
        
        # Upload proof for the deposit
        files = {
            "proof_image": ("test_screenshot.png", io.BytesIO(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91h6\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9'), "image/png")
        }
        
        upload_response = requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/upload-proof",
            headers=headers,
            files=files
        )
        
        assert upload_response.status_code == 200, f"Upload proof failed: {upload_response.text}"
        
        data = upload_response.json()
        assert "message" in data
        assert data["transaction_id"] == transaction_id
        print(f"✓ Upload proof works for deposits: {transaction_id}")
    
    def test_deposit_approval_requires_proof(self, admin_token, test_client_id, test_treasury_id):
        """Test that deposit approval fails without proof of payment"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create a pending deposit transaction
        tx_response = create_test_transaction(
            headers, test_client_id, test_treasury_id,
            "deposit", 500, "TEST_DepositNoProof002"
        )
        assert tx_response.status_code in [200, 201], f"Failed to create transaction: {tx_response.text}"
        
        transaction = tx_response.json()
        transaction_id = transaction["transaction_id"]
        
        # Try to approve without uploading proof
        approve_response = requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/approve",
            headers=headers
        )
        
        assert approve_response.status_code == 400, f"Expected 400 but got {approve_response.status_code}: {approve_response.text}"
        assert "proof" in approve_response.text.lower() or "screenshot" in approve_response.text.lower() or "required" in approve_response.text.lower()
        print(f"✓ Deposit approval correctly requires proof of payment")
    
    def test_deposit_approval_succeeds_with_proof(self, admin_token, test_client_id, test_treasury_id):
        """Test that deposit approval succeeds when proof is uploaded first"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create a pending deposit transaction
        tx_response = create_test_transaction(
            headers, test_client_id, test_treasury_id,
            "deposit", 750, "TEST_DepositWithProof003"
        )
        assert tx_response.status_code in [200, 201], f"Failed to create transaction: {tx_response.text}"
        
        transaction = tx_response.json()
        transaction_id = transaction["transaction_id"]
        
        # First upload proof
        files = {
            "proof_image": ("deposit_proof.png", io.BytesIO(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91h6\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9'), "image/png")
        }
        
        upload_response = requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/upload-proof",
            headers=headers,
            files=files
        )
        assert upload_response.status_code == 200, f"Upload proof failed: {upload_response.text}"
        
        # Now approve should succeed
        approve_response = requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/approve",
            headers=headers
        )
        
        assert approve_response.status_code == 200, f"Approval failed: {approve_response.text}"
        
        approved_tx = approve_response.json()
        assert approved_tx["status"] == "approved", f"Status should be approved: {approved_tx}"
        print(f"✓ Deposit approved successfully with proof: {transaction_id}")
    
    def test_approved_deposit_has_accountant_proof_image(self, admin_token, test_client_id, test_treasury_id):
        """Test that approved deposit with proof has accountant_proof_image field"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create deposit
        tx_response = create_test_transaction(
            headers, test_client_id, test_treasury_id,
            "deposit", 850, "TEST_DepositCheckImage004"
        )
        assert tx_response.status_code in [200, 201]
        
        transaction = tx_response.json()
        transaction_id = transaction["transaction_id"]
        
        # Upload proof
        files = {
            "proof_image": ("proof.png", io.BytesIO(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91h6'), "image/png")
        }
        
        requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/upload-proof",
            headers=headers,
            files=files
        )
        
        # Approve
        requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/approve",
            headers=headers
        )
        
        # Fetch transaction and verify accountant_proof_image exists
        get_response = requests.get(
            f"{BASE_URL}/api/transactions",
            headers=headers
        )
        
        assert get_response.status_code == 200
        transactions = get_response.json()
        
        # Find our transaction
        tx = next((t for t in transactions if t.get("transaction_id") == transaction_id), None)
        assert tx is not None, f"Transaction {transaction_id} not found"
        assert "accountant_proof_image" in tx, f"accountant_proof_image not in transaction: {tx.keys()}"
        assert tx["accountant_proof_image"] is not None, "accountant_proof_image should not be None"
        print(f"✓ Approved deposit has accountant_proof_image field: {transaction_id}")
    
    def test_accountant_can_approve_deposits(self, accountant_token, admin_token, test_client_id, test_treasury_id):
        """Test that accountant role can approve deposits with proof"""
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        acct_headers = {"Authorization": f"Bearer {accountant_token}"}
        
        # Create deposit as admin
        tx_response = create_test_transaction(
            admin_headers, test_client_id, test_treasury_id,
            "deposit", 600, "TEST_AccountantApproval005"
        )
        assert tx_response.status_code in [200, 201]
        
        transaction = tx_response.json()
        transaction_id = transaction["transaction_id"]
        
        # Accountant uploads proof and approves
        files = {
            "proof_image": ("acct_proof.png", io.BytesIO(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'), "image/png")
        }
        
        upload_response = requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/upload-proof",
            headers=acct_headers,
            files=files
        )
        assert upload_response.status_code == 200, f"Accountant upload failed: {upload_response.text}"
        
        approve_response = requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/approve",
            headers=acct_headers
        )
        assert approve_response.status_code == 200, f"Accountant approval failed: {approve_response.text}"
        
        approved_tx = approve_response.json()
        assert approved_tx["status"] == "approved"
        print(f"✓ Accountant can approve deposits with proof: {transaction_id}")


class TestWithdrawalApprovalStillWorks:
    """Ensure existing withdrawal approval flow still works"""
    
    def test_withdrawal_approval_requires_source_account(self, admin_token, test_client_id, test_treasury_id):
        """Test that withdrawal approval requires source account"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create withdrawal with bank destination (using Form data)
        data = {
            "client_id": test_client_id,
            "transaction_type": "withdrawal",
            "amount": 200,
            "currency": "USD",
            "destination_type": "bank",
            "client_bank_name": "Test Bank",
            "client_bank_account_name": "Test Account",
            "client_bank_account_number": "12345678",
            "reference": "TEST_WithdrawalSrcAcct006"
        }
        
        tx_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers=headers,
            data=data
        )
        assert tx_response.status_code in [200, 201], f"Failed to create withdrawal: {tx_response.text}"
        
        transaction = tx_response.json()
        transaction_id = transaction["transaction_id"]
        
        # Try approve without source account
        approve_response = requests.post(
            f"{BASE_URL}/api/transactions/{transaction_id}/approve",
            headers=headers
        )
        
        assert approve_response.status_code == 400, f"Expected 400: {approve_response.text}"
        assert "source" in approve_response.text.lower()
        print(f"✓ Withdrawal approval requires source account")


class TestPendingTransactionsAPI:
    """Test pending transactions endpoint for approvals page"""
    
    def test_pending_deposits_appear_in_pending_list(self, admin_token, test_client_id, test_treasury_id):
        """Test that pending deposits appear in pending transactions"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create a pending deposit
        tx_response = create_test_transaction(
            headers, test_client_id, test_treasury_id,
            "deposit", 999, "TEST_PendingDeposit008"
        )
        assert tx_response.status_code in [200, 201]
        
        transaction = tx_response.json()
        transaction_id = transaction["transaction_id"]
        
        # Get pending transactions
        pending_response = requests.get(
            f"{BASE_URL}/api/transactions/pending",
            headers=headers
        )
        
        assert pending_response.status_code == 200
        pending = pending_response.json()
        
        # Find our pending deposit
        deposit = next((t for t in pending if t.get("transaction_id") == transaction_id), None)
        assert deposit is not None, f"Pending deposit not found in list"
        assert deposit["transaction_type"] == "deposit"
        assert deposit["status"] == "pending"
        print(f"✓ Pending deposit appears in pending-transactions list")


# Cleanup fixture
@pytest.fixture(autouse=True, scope="module")
def cleanup(admin_token):
    """Cleanup test data after module completes"""
    yield
    
    if not admin_token:
        return
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Get all transactions and delete TEST_ prefixed ones
    try:
        response = requests.get(f"{BASE_URL}/api/transactions", headers=headers)
        if response.status_code == 200:
            transactions = response.json()
            for tx in transactions:
                if tx.get("reference", "").startswith("TEST_"):
                    # Try to reject/cancel test transactions
                    requests.post(
                        f"{BASE_URL}/api/transactions/{tx['transaction_id']}/reject",
                        headers=headers,
                        json={"reason": "Test cleanup"}
                    )
    except Exception as e:
        print(f"Cleanup warning: {e}")
