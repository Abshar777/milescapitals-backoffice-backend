"""
Test new Transaction features:
1. Destination Types (treasury, bank, usdt, psp, vendor)
2. Client Bank Details for withdrawals
3. Client USDT Details for withdrawals  
4. USDT Treasury accounts with wallet address/network
5. Upload proof for withdrawals
6. Approvals page shows bank/USDT details
"""
import pytest
import requests
import os
import io
import base64

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestDestinationTypes:
    """Test the 5 destination types: Treasury, Client Bank, USDT, PSP, Vendor"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        # Login as admin
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "admin123"
        })
        assert response.status_code == 200, f"Admin login failed: {response.text}"
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
        
        # Get clients
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=self.headers)
        assert clients_resp.status_code == 200
        self.clients = clients_resp.json()
        assert len(self.clients) > 0, "No clients found - need seeded data"
        self.test_client = self.clients[0]
        
        # Get treasury accounts
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        assert treasury_resp.status_code == 200
        self.treasury_accounts = treasury_resp.json()
        
        # Get PSPs
        psps_resp = requests.get(f"{BASE_URL}/api/psp", headers=self.headers)
        assert psps_resp.status_code == 200
        self.psps = psps_resp.json()
        
        # Get vendors
        vendors_resp = requests.get(f"{BASE_URL}/api/vendors", headers=self.headers)
        assert vendors_resp.status_code == 200
        self.vendors = vendors_resp.json()
    
    def test_withdrawal_to_client_bank_no_treasury_selector(self):
        """Test: Withdrawal + Client Bank does NOT require treasury selector, only client bank details"""
        form_data = {
            "client_id": self.test_client["client_id"],
            "transaction_type": "withdrawal",
            "amount": "150.00",
            "currency": "USD",
            "destination_type": "bank",
            # Client bank details
            "client_bank_name": "Chase Bank",
            "client_bank_account_name": "Test Account Holder",
            "client_bank_account_number": "123456789",
            "client_bank_swift_iban": "CHASUS33",
            "client_bank_currency": "USD",
            # NO destination_account_id required for bank type
        }
        
        response = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert response.status_code == 200, f"Failed to create bank withdrawal: {response.text}"
        
        tx = response.json()
        assert tx["destination_type"] == "bank"
        assert tx["client_bank_name"] == "Chase Bank"
        assert tx["client_bank_account_name"] == "Test Account Holder"
        assert tx["client_bank_account_number"] == "123456789"
        assert tx["client_bank_swift_iban"] == "CHASUS33"
        assert tx["client_bank_currency"] == "USD"
        # destination_account_id should be None for bank type
        assert tx.get("destination_account_id") is None
        print(f"✓ Bank withdrawal created successfully: {tx['transaction_id']}")
    
    def test_withdrawal_to_usdt_client_address(self):
        """Test: Withdrawal + USDT shows client USDT address and network"""
        form_data = {
            "client_id": self.test_client["client_id"],
            "transaction_type": "withdrawal",
            "amount": "200.00",
            "currency": "USD",
            "destination_type": "usdt",
            # Client USDT details
            "client_usdt_address": "TQV5nUFfKXFrb8UNcYGkU3F2zBWPhDJMVN",
            "client_usdt_network": "TRC20",
            # NO destination_account_id for USDT withdrawal
        }
        
        response = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert response.status_code == 200, f"Failed to create USDT withdrawal: {response.text}"
        
        tx = response.json()
        assert tx["destination_type"] == "usdt"
        assert tx["client_usdt_address"] == "TQV5nUFfKXFrb8UNcYGkU3F2zBWPhDJMVN"
        assert tx["client_usdt_network"] == "TRC20"
        print(f"✓ USDT withdrawal created successfully: {tx['transaction_id']}")

    def test_deposit_to_treasury(self):
        """Test: Deposit to Treasury requires destination_account_id"""
        if not self.treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        # Get a non-USDT treasury account
        bank_accounts = [a for a in self.treasury_accounts if a.get("account_type") != "usdt"]
        if not bank_accounts:
            pytest.skip("No bank treasury accounts available")
        
        treasury = bank_accounts[0]
        form_data = {
            "client_id": self.test_client["client_id"],
            "transaction_type": "deposit",
            "amount": "500.00",
            "currency": "USD",
            "destination_type": "treasury",
            "destination_account_id": treasury["account_id"],
        }
        
        response = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert response.status_code == 200, f"Failed to create treasury deposit: {response.text}"
        
        tx = response.json()
        assert tx["destination_type"] == "treasury"
        assert tx["destination_account_id"] == treasury["account_id"]
        print(f"✓ Treasury deposit created successfully: {tx['transaction_id']}")

    def test_deposit_to_psp(self):
        """Test: Deposit via PSP"""
        active_psps = [p for p in self.psps if p.get("status") == "active"]
        if not active_psps:
            pytest.skip("No active PSPs available")
        
        psp = active_psps[0]
        form_data = {
            "client_id": self.test_client["client_id"],
            "transaction_type": "deposit",
            "amount": "300.00",
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": psp["psp_id"],
            "commission_paid_by": "client",
        }
        
        response = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert response.status_code == 200, f"Failed to create PSP deposit: {response.text}"
        
        tx = response.json()
        assert tx["destination_type"] == "psp"
        assert tx["psp_id"] == psp["psp_id"]
        print(f"✓ PSP deposit created successfully: {tx['transaction_id']}")

    def test_deposit_to_vendor(self):
        """Test: Deposit via Vendor"""
        active_vendors = [v for v in self.vendors if v.get("status") == "active"]
        if not active_vendors:
            pytest.skip("No active vendors available")
        
        vendor = active_vendors[0]
        form_data = {
            "client_id": self.test_client["client_id"],
            "transaction_type": "deposit",
            "amount": "400.00",
            "currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor["vendor_id"],
        }
        
        response = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert response.status_code == 200, f"Failed to create vendor deposit: {response.text}"
        
        tx = response.json()
        assert tx["destination_type"] == "vendor"
        assert tx["vendor_id"] == vendor["vendor_id"]
        print(f"✓ Vendor deposit created successfully: {tx['transaction_id']}")


class TestUSDTTreasury:
    """Test USDT Treasury Account creation with wallet address, network, notes"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        # Login as admin
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "admin123"
        })
        assert response.status_code == 200
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
    
    def test_create_usdt_treasury_account(self):
        """Test: Create USDT wallet account with address, network, and notes"""
        usdt_account_data = {
            "account_name": "TEST USDT TRC20 Wallet",
            "account_type": "usdt",
            "currency": "USDT",
            "usdt_address": "TRx1234567890TestWalletAddress",
            "usdt_network": "TRC20",
            "usdt_notes": "Test USDT wallet for testing purposes",
            "description": "Test USDT Treasury Account"
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury", headers=self.headers, json=usdt_account_data)
        assert response.status_code == 200, f"Failed to create USDT treasury: {response.text}"
        
        account = response.json()
        assert account["account_type"] == "usdt"
        assert account["usdt_address"] == "TRx1234567890TestWalletAddress"
        assert account["usdt_network"] == "TRC20"
        assert account["usdt_notes"] == "Test USDT wallet for testing purposes"
        assert account["currency"] == "USDT"
        
        # Clean up - delete the test account
        delete_resp = requests.delete(f"{BASE_URL}/api/treasury/{account['account_id']}", headers=self.headers)
        assert delete_resp.status_code == 200
        
        print(f"✓ USDT Treasury account created and cleaned up: {account['account_id']}")

    def test_deposit_to_usdt_treasury(self):
        """Test: USDT deposit selects USDT treasury account"""
        # First create a USDT treasury account
        usdt_account_data = {
            "account_name": "TEST USDT Deposit Wallet",
            "account_type": "usdt",
            "currency": "USDT",
            "usdt_address": "TRxDepositTestWalletAddress",
            "usdt_network": "ERC20",
            "usdt_notes": "For USDT deposits"
        }
        
        create_resp = requests.post(f"{BASE_URL}/api/treasury", headers=self.headers, json=usdt_account_data)
        assert create_resp.status_code == 200
        usdt_account = create_resp.json()
        
        # Get a client
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=self.headers)
        assert clients_resp.status_code == 200
        clients = clients_resp.json()
        if not clients:
            requests.delete(f"{BASE_URL}/api/treasury/{usdt_account['account_id']}", headers=self.headers)
            pytest.skip("No clients available")
        
        # Create a USDT deposit to the USDT treasury account
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "1000.00",
            "currency": "USD",
            "destination_type": "usdt",
            "destination_account_id": usdt_account["account_id"],
        }
        
        tx_resp = requests.post(
            f"{BASE_URL}/api/transactions", 
            headers={"Authorization": f"Bearer {self.token}"}, 
            data=form_data
        )
        assert tx_resp.status_code == 200, f"Failed to create USDT deposit: {tx_resp.text}"
        
        tx = tx_resp.json()
        assert tx["destination_type"] == "usdt"
        assert tx["destination_account_id"] == usdt_account["account_id"]
        
        # Clean up
        requests.delete(f"{BASE_URL}/api/treasury/{usdt_account['account_id']}", headers=self.headers)
        
        print(f"✓ USDT deposit to USDT treasury created: {tx['transaction_id']}")


class TestUploadProof:
    """Test upload proof functionality for withdrawals"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        # Login as admin
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "admin123"
        })
        assert response.status_code == 200
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
        
        # Get clients
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=self.headers)
        assert clients_resp.status_code == 200
        self.clients = clients_resp.json()
        
    def test_upload_proof_for_withdrawal(self):
        """Test: Upload proof screenshot for withdrawal transaction"""
        if not self.clients:
            pytest.skip("No clients available")
        
        # Create a withdrawal transaction first
        form_data = {
            "client_id": self.clients[0]["client_id"],
            "transaction_type": "withdrawal",
            "amount": "100.00",
            "currency": "USD",
            "destination_type": "bank",
            "client_bank_name": "Test Bank",
            "client_bank_account_name": "Test Account",
            "client_bank_account_number": "987654321",
            "client_bank_currency": "USD",
        }
        
        tx_resp = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert tx_resp.status_code == 200
        tx = tx_resp.json()
        tx_id = tx["transaction_id"]
        
        # Create a simple test image (1x1 PNG)
        png_data = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        )
        
        # Upload proof
        files = {"proof_image": ("test_proof.png", io.BytesIO(png_data), "image/png")}
        upload_resp = requests.post(
            f"{BASE_URL}/api/transactions/{tx_id}/upload-proof",
            headers={"Authorization": f"Bearer {self.token}"},
            files=files
        )
        assert upload_resp.status_code == 200, f"Upload failed: {upload_resp.text}"
        
        result = upload_resp.json()
        assert result["message"] == "Proof uploaded successfully"
        assert result["transaction_id"] == tx_id
        
        # Verify proof was stored
        get_resp = requests.get(f"{BASE_URL}/api/transactions/{tx_id}", headers=self.headers)
        assert get_resp.status_code == 200
        updated_tx = get_resp.json()
        assert updated_tx.get("accountant_proof_image") is not None
        
        print(f"✓ Proof uploaded successfully for withdrawal: {tx_id}")

    def test_upload_proof_only_for_withdrawals(self):
        """Test: Upload proof is only allowed for withdrawal transactions"""
        if not self.clients:
            pytest.skip("No clients available")
        
        # Get treasury accounts
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        assert treasury_resp.status_code == 200
        treasury_accounts = treasury_resp.json()
        
        if not treasury_accounts:
            pytest.skip("No treasury accounts available")
        
        # Create a deposit transaction
        bank_accounts = [a for a in treasury_accounts if a.get("account_type") != "usdt"]
        if not bank_accounts:
            pytest.skip("No bank treasury accounts")
        
        form_data = {
            "client_id": self.clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "100.00",
            "currency": "USD",
            "destination_type": "treasury",
            "destination_account_id": bank_accounts[0]["account_id"],
        }
        
        tx_resp = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert tx_resp.status_code == 200
        tx = tx_resp.json()
        tx_id = tx["transaction_id"]
        
        # Try to upload proof for deposit - should fail
        png_data = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        )
        files = {"proof_image": ("test_proof.png", io.BytesIO(png_data), "image/png")}
        upload_resp = requests.post(
            f"{BASE_URL}/api/transactions/{tx_id}/upload-proof",
            headers={"Authorization": f"Bearer {self.token}"},
            files=files
        )
        assert upload_resp.status_code == 400
        assert "withdrawal" in upload_resp.json()["detail"].lower()
        
        print(f"✓ Upload proof correctly rejected for deposit transaction")


class TestPendingApprovalsDetails:
    """Test that Approvals page shows client bank/USDT details"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        # Login as admin
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "admin123"
        })
        assert response.status_code == 200
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
        
        # Get clients
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=self.headers)
        assert clients_resp.status_code == 200
        self.clients = clients_resp.json()

    def test_pending_transactions_include_bank_details(self):
        """Test: Pending transactions endpoint includes client bank details"""
        if not self.clients:
            pytest.skip("No clients available")
        
        # Create a bank withdrawal that will be pending
        form_data = {
            "client_id": self.clients[0]["client_id"],
            "transaction_type": "withdrawal",
            "amount": "250.00",
            "currency": "USD",
            "destination_type": "bank",
            "client_bank_name": "Citibank",
            "client_bank_account_name": "John Doe",
            "client_bank_account_number": "111222333",
            "client_bank_swift_iban": "CITIUS33",
            "client_bank_currency": "EUR",
        }
        
        tx_resp = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert tx_resp.status_code == 200
        created_tx = tx_resp.json()
        
        # Get pending transactions
        pending_resp = requests.get(f"{BASE_URL}/api/transactions/pending", headers=self.headers)
        assert pending_resp.status_code == 200
        pending_txs = pending_resp.json()
        
        # Find our transaction
        our_tx = next((t for t in pending_txs if t["transaction_id"] == created_tx["transaction_id"]), None)
        assert our_tx is not None, "Created transaction not found in pending list"
        
        # Verify bank details are included
        assert our_tx.get("client_bank_name") == "Citibank"
        assert our_tx.get("client_bank_account_number") == "111222333"
        assert our_tx.get("client_bank_swift_iban") == "CITIUS33"
        assert our_tx.get("client_bank_currency") == "EUR"
        
        print(f"✓ Pending transactions include bank details")

    def test_pending_transactions_include_usdt_details(self):
        """Test: Pending transactions endpoint includes client USDT details"""
        if not self.clients:
            pytest.skip("No clients available")
        
        # Create a USDT withdrawal that will be pending
        form_data = {
            "client_id": self.clients[0]["client_id"],
            "transaction_type": "withdrawal",
            "amount": "350.00",
            "currency": "USD",
            "destination_type": "usdt",
            "client_usdt_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f12B98",
            "client_usdt_network": "ERC20",
        }
        
        tx_resp = requests.post(f"{BASE_URL}/api/transactions", headers=self.headers, data=form_data)
        assert tx_resp.status_code == 200
        created_tx = tx_resp.json()
        
        # Get pending transactions
        pending_resp = requests.get(f"{BASE_URL}/api/transactions/pending", headers=self.headers)
        assert pending_resp.status_code == 200
        pending_txs = pending_resp.json()
        
        # Find our transaction
        our_tx = next((t for t in pending_txs if t["transaction_id"] == created_tx["transaction_id"]), None)
        assert our_tx is not None, "Created transaction not found in pending list"
        
        # Verify USDT details are included
        assert our_tx.get("client_usdt_address") == "0x742d35Cc6634C0532925a3b844Bc9e7595f12B98"
        assert our_tx.get("client_usdt_network") == "ERC20"
        
        print(f"✓ Pending transactions include USDT details")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
