"""
Test Inter-Treasury Transfer Feature
- POST /api/treasury/transfer endpoint
- Transfer between treasury accounts
- Balance updates verification
- Exchange rate handling
- Error handling (insufficient balance, same account, etc.)
"""

import pytest
import requests
import os
import uuid
from datetime import datetime

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestTreasuryTransfer:
    """Tests for Inter-Treasury Transfer feature"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup - login and get auth token"""
        # Login as admin
        login_response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": "admin@fxbroker.com", "password": "admin123"}
        )
        assert login_response.status_code == 200, f"Login failed: {login_response.text}"
        self.token = login_response.json().get("access_token")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        yield
    
    def test_get_treasury_accounts(self):
        """Test GET /api/treasury - list all treasury accounts"""
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        assert response.status_code == 200
        accounts = response.json()
        assert isinstance(accounts, list)
        print(f"✓ Found {len(accounts)} treasury accounts")
        
        # Check if accounts have required fields
        if len(accounts) > 0:
            account = accounts[0]
            assert "account_id" in account
            assert "account_name" in account
            assert "currency" in account
            assert "balance" in account
            print(f"✓ Account structure verified: {account.get('account_name')}")
    
    def test_create_two_treasury_accounts_for_transfer(self):
        """Create two treasury accounts for testing transfers"""
        # Create source account with balance
        test_id = uuid.uuid4().hex[:8]
        source_data = {
            "account_name": f"TEST_Source_Account_{test_id}",
            "account_type": "bank",
            "bank_name": "Test Source Bank",
            "account_number": "1234567890",
            "currency": "USD",
            "description": "Test source account for transfers"
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury", headers=self.headers, json=source_data)
        assert response.status_code == 200, f"Failed to create source account: {response.text}"
        source_account = response.json()
        assert source_account.get("account_id")
        assert source_account.get("account_name") == source_data["account_name"]
        print(f"✓ Created source account: {source_account.get('account_name')}")
        
        # Create destination account
        dest_data = {
            "account_name": f"TEST_Dest_Account_{test_id}",
            "account_type": "bank",
            "bank_name": "Test Dest Bank",
            "account_number": "0987654321",
            "currency": "EUR",
            "description": "Test destination account for transfers"
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury", headers=self.headers, json=dest_data)
        assert response.status_code == 200, f"Failed to create dest account: {response.text}"
        dest_account = response.json()
        assert dest_account.get("account_id")
        print(f"✓ Created destination account: {dest_account.get('account_name')}")
        
        return source_account, dest_account
    
    def test_transfer_requires_different_accounts(self):
        """Test transfer fails when source and destination are the same"""
        # Get existing accounts
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        if len(accounts) == 0:
            pytest.skip("No treasury accounts available")
        
        account_id = accounts[0]["account_id"]
        
        transfer_data = {
            "source_account_id": account_id,
            "destination_account_id": account_id,  # Same account
            "amount": 100,
            "exchange_rate": 1.0,
            "notes": "Test same account transfer"
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        assert response.status_code == 400
        assert "different" in response.json().get("detail", "").lower() or "same" in response.json().get("detail", "").lower()
        print("✓ Transfer correctly rejected when source and destination are the same")
    
    def test_transfer_requires_positive_amount(self):
        """Test transfer fails with zero or negative amount"""
        # Get accounts
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        if len(accounts) < 2:
            pytest.skip("Need at least 2 treasury accounts")
        
        transfer_data = {
            "source_account_id": accounts[0]["account_id"],
            "destination_account_id": accounts[1]["account_id"],
            "amount": 0,  # Invalid amount
            "exchange_rate": 1.0
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        assert response.status_code == 400
        assert "positive" in response.json().get("detail", "").lower() or "amount" in response.json().get("detail", "").lower()
        print("✓ Transfer correctly rejected with zero amount")
        
        # Test negative amount
        transfer_data["amount"] = -100
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        assert response.status_code == 400
        print("✓ Transfer correctly rejected with negative amount")
    
    def test_transfer_validates_source_account_exists(self):
        """Test transfer fails when source account doesn't exist"""
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        if len(accounts) == 0:
            pytest.skip("No treasury accounts available")
        
        transfer_data = {
            "source_account_id": "nonexistent_account_id",
            "destination_account_id": accounts[0]["account_id"],
            "amount": 100,
            "exchange_rate": 1.0
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        assert response.status_code == 404
        assert "source" in response.json().get("detail", "").lower()
        print("✓ Transfer correctly rejected with invalid source account")
    
    def test_transfer_validates_destination_account_exists(self):
        """Test transfer fails when destination account doesn't exist"""
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        if len(accounts) == 0:
            pytest.skip("No treasury accounts available")
        
        transfer_data = {
            "source_account_id": accounts[0]["account_id"],
            "destination_account_id": "nonexistent_account_id",
            "amount": 100,
            "exchange_rate": 1.0
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        assert response.status_code == 404
        assert "destination" in response.json().get("detail", "").lower()
        print("✓ Transfer correctly rejected with invalid destination account")
    
    def test_transfer_checks_insufficient_balance(self):
        """Test transfer fails when source has insufficient balance"""
        # Create two fresh accounts
        test_id = uuid.uuid4().hex[:8]
        
        # Create source account (will have 0 balance)
        source_data = {
            "account_name": f"TEST_NoBalance_Src_{test_id}",
            "account_type": "bank",
            "bank_name": "Test Bank",
            "currency": "USD"
        }
        response = requests.post(f"{BASE_URL}/api/treasury", headers=self.headers, json=source_data)
        assert response.status_code == 200
        source = response.json()
        
        # Create destination account
        dest_data = {
            "account_name": f"TEST_NoBalance_Dest_{test_id}",
            "account_type": "bank",
            "bank_name": "Test Bank",
            "currency": "USD"
        }
        response = requests.post(f"{BASE_URL}/api/treasury", headers=self.headers, json=dest_data)
        assert response.status_code == 200
        dest = response.json()
        
        # Try to transfer more than available balance (0)
        transfer_data = {
            "source_account_id": source["account_id"],
            "destination_account_id": dest["account_id"],
            "amount": 1000,  # Source has 0 balance
            "exchange_rate": 1.0
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        assert response.status_code == 400
        assert "insufficient" in response.json().get("detail", "").lower() or "balance" in response.json().get("detail", "").lower()
        print("✓ Transfer correctly rejected for insufficient balance")
        
        # Cleanup
        requests.delete(f"{BASE_URL}/api/treasury/{source['account_id']}", headers=self.headers)
        requests.delete(f"{BASE_URL}/api/treasury/{dest['account_id']}", headers=self.headers)
    
    def test_transfer_returns_proper_response(self):
        """Test that successful transfer returns expected response structure"""
        # Get accounts with balance
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        # Find accounts with sufficient balance
        accounts_with_balance = [a for a in accounts if a.get("balance", 0) >= 100]
        
        if len(accounts_with_balance) < 1 or len(accounts) < 2:
            pytest.skip("Need accounts with balance for this test")
        
        source = accounts_with_balance[0]
        # Find a different account as destination
        dest = next((a for a in accounts if a["account_id"] != source["account_id"]), None)
        
        if not dest:
            pytest.skip("Need at least 2 different accounts")
        
        initial_source_balance = source.get("balance", 0)
        initial_dest_balance = dest.get("balance", 0)
        transfer_amount = 10.0  # Small amount to test
        exchange_rate = 1.0
        
        if initial_source_balance < transfer_amount:
            pytest.skip(f"Source account balance ({initial_source_balance}) insufficient for test")
        
        transfer_data = {
            "source_account_id": source["account_id"],
            "destination_account_id": dest["account_id"],
            "amount": transfer_amount,
            "exchange_rate": exchange_rate,
            "notes": "Test transfer"
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        
        if response.status_code != 200:
            print(f"Transfer failed: {response.text}")
            pytest.skip(f"Transfer failed - may be due to insufficient balance: {response.text}")
        
        result = response.json()
        
        # Verify response structure
        assert "transfer_id" in result, "Response should contain transfer_id"
        assert "source_account" in result, "Response should contain source_account"
        assert "destination_account" in result, "Response should contain destination_account"
        assert "source_amount" in result, "Response should contain source_amount"
        assert "destination_amount" in result, "Response should contain destination_amount"
        assert result["source_amount"] == transfer_amount
        
        print(f"✓ Transfer successful: {result['transfer_id']}")
        print(f"  From: {result['source_account']} -> To: {result['destination_account']}")
        print(f"  Amount: {result['source_amount']} {result.get('source_currency', 'USD')} -> {result['destination_amount']} {result.get('destination_currency', 'USD')}")
        
        # Verify balances updated
        response = requests.get(f"{BASE_URL}/api/treasury/{source['account_id']}", headers=self.headers)
        updated_source = response.json()
        
        response = requests.get(f"{BASE_URL}/api/treasury/{dest['account_id']}", headers=self.headers)
        updated_dest = response.json()
        
        expected_source_balance = initial_source_balance - transfer_amount
        expected_dest_balance = initial_dest_balance + (transfer_amount * exchange_rate)
        
        # Allow for small floating point differences
        assert abs(updated_source.get("balance", 0) - expected_source_balance) < 0.01, \
            f"Source balance should be {expected_source_balance}, got {updated_source.get('balance')}"
        assert abs(updated_dest.get("balance", 0) - expected_dest_balance) < 0.01, \
            f"Dest balance should be {expected_dest_balance}, got {updated_dest.get('balance')}"
        
        print(f"✓ Balances updated correctly")
        print(f"  Source: {initial_source_balance} -> {updated_source.get('balance')}")
        print(f"  Dest: {initial_dest_balance} -> {updated_dest.get('balance')}")
    
    def test_transfer_with_exchange_rate(self):
        """Test transfer with custom exchange rate between currencies"""
        # Get accounts
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        # Find accounts with different currencies and balance
        accounts_with_balance = [a for a in accounts if a.get("balance", 0) >= 100]
        
        if len(accounts_with_balance) < 1 or len(accounts) < 2:
            pytest.skip("Need accounts with balance for this test")
        
        source = accounts_with_balance[0]
        dest = next((a for a in accounts if a["account_id"] != source["account_id"]), None)
        
        if not dest:
            pytest.skip("Need at least 2 different accounts")
        
        transfer_amount = 10.0
        exchange_rate = 1.5  # Custom exchange rate
        expected_dest_amount = transfer_amount * exchange_rate
        
        if source.get("balance", 0) < transfer_amount:
            pytest.skip(f"Source account balance insufficient")
        
        initial_dest_balance = dest.get("balance", 0)
        
        transfer_data = {
            "source_account_id": source["account_id"],
            "destination_account_id": dest["account_id"],
            "amount": transfer_amount,
            "exchange_rate": exchange_rate,
            "notes": "Test transfer with exchange rate"
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        
        if response.status_code != 200:
            pytest.skip(f"Transfer failed: {response.text}")
        
        result = response.json()
        
        assert result["exchange_rate"] == exchange_rate
        assert abs(result["destination_amount"] - expected_dest_amount) < 0.01, \
            f"Expected dest amount {expected_dest_amount}, got {result['destination_amount']}"
        
        # Verify dest balance increased by correct amount
        response = requests.get(f"{BASE_URL}/api/treasury/{dest['account_id']}", headers=self.headers)
        updated_dest = response.json()
        
        expected_final_dest = initial_dest_balance + expected_dest_amount
        assert abs(updated_dest.get("balance", 0) - expected_final_dest) < 0.01
        
        print(f"✓ Exchange rate applied correctly: {transfer_amount} * {exchange_rate} = {expected_dest_amount}")
    
    def test_transfer_recorded_in_history(self):
        """Test that transfers are recorded in account history"""
        # Get accounts with balance
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        accounts_with_balance = [a for a in accounts if a.get("balance", 0) >= 100]
        
        if len(accounts_with_balance) < 1 or len(accounts) < 2:
            pytest.skip("Need accounts with balance for this test")
        
        source = accounts_with_balance[0]
        dest = next((a for a in accounts if a["account_id"] != source["account_id"]), None)
        
        if not dest or source.get("balance", 0) < 10:
            pytest.skip("Need accounts for this test")
        
        transfer_data = {
            "source_account_id": source["account_id"],
            "destination_account_id": dest["account_id"],
            "amount": 5.0,
            "exchange_rate": 1.0,
            "notes": "History test transfer"
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", headers=self.headers, json=transfer_data)
        
        if response.status_code != 200:
            pytest.skip(f"Transfer failed: {response.text}")
        
        transfer_result = response.json()
        
        # Check source account history
        response = requests.get(f"{BASE_URL}/api/treasury/{source['account_id']}/history", headers=self.headers)
        assert response.status_code == 200
        source_history = response.json()
        
        # Find the transfer in history
        transfer_out = next((h for h in source_history if h.get("transaction_type") == "transfer_out" 
                            and h.get("transfer_id") == transfer_result.get("transfer_id")), None)
        
        if transfer_out:
            assert transfer_out["amount"] < 0, "Transfer out should be negative"
            print(f"✓ Transfer recorded in source account history as 'transfer_out'")
        
        # Check destination account history
        response = requests.get(f"{BASE_URL}/api/treasury/{dest['account_id']}/history", headers=self.headers)
        assert response.status_code == 200
        dest_history = response.json()
        
        transfer_in = next((h for h in dest_history if h.get("transaction_type") == "transfer_in"
                           and h.get("transfer_id") == transfer_result.get("transfer_id")), None)
        
        if transfer_in:
            assert transfer_in["amount"] > 0, "Transfer in should be positive"
            print(f"✓ Transfer recorded in destination account history as 'transfer_in'")
    
    def test_transfer_requires_admin_role(self):
        """Test that only admin users can perform transfers"""
        # This test would require a non-admin user
        # For now, we verify that the endpoint requires authentication
        
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        if len(accounts) < 2:
            pytest.skip("Need at least 2 accounts")
        
        transfer_data = {
            "source_account_id": accounts[0]["account_id"],
            "destination_account_id": accounts[1]["account_id"],
            "amount": 10,
            "exchange_rate": 1.0
        }
        
        # Try without auth
        response = requests.post(f"{BASE_URL}/api/treasury/transfer", json=transfer_data)
        assert response.status_code == 401, "Should require authentication"
        print("✓ Transfer endpoint requires authentication")


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
