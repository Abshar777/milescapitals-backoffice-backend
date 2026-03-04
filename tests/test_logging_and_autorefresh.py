"""
Test Suite for Logging and Auto-refresh Features
Tests:
1. POST /api/transactions creates transaction AND generates activity log in 'transactions' module
2. GET /api/logs?module=transactions returns transaction logs
3. GET /api/logs?module=clients returns client logs
4. GET /api/logs (all logs) returns logs from multiple modules
5. GET /api/logs/stats returns stats with module breakdown
"""

import pytest
import requests
import os
import uuid
from datetime import datetime

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL').rstrip('/')

# Test credentials
ADMIN_EMAIL = "admin@fxbroker.com"
ADMIN_PASSWORD = "admin123"

@pytest.fixture(scope="module")
def admin_token():
    """Get admin authentication token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD
    })
    assert response.status_code == 200, f"Admin login failed: {response.text}"
    return response.json()["access_token"]

@pytest.fixture(scope="module")
def auth_headers(admin_token):
    """Return headers with admin auth token"""
    return {"Authorization": f"Bearer {admin_token}"}

@pytest.fixture(scope="module")
def test_client(auth_headers):
    """Create a test client for transaction testing"""
    unique_id = uuid.uuid4().hex[:8]
    client_data = {
        "first_name": f"LogTest_{unique_id}",
        "last_name": "Client",
        "email": f"logtest_{unique_id}@test.com",
        "phone": "+1234567890",
        "country": "US"
    }
    response = requests.post(f"{BASE_URL}/api/clients", json=client_data, headers=auth_headers)
    assert response.status_code == 200, f"Failed to create test client: {response.text}"
    return response.json()

@pytest.fixture(scope="module")
def test_treasury_account(auth_headers):
    """Get or create treasury account for transactions"""
    # First try to get existing
    response = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers)
    if response.status_code == 200:
        accounts = response.json()
        if accounts:
            return accounts[0]
    
    # Create one if none exist
    unique_id = uuid.uuid4().hex[:8]
    account_data = {
        "account_name": f"LogTest_Treasury_{unique_id}",
        "account_type": "bank",
        "bank_name": "Test Bank",
        "currency": "USD",
        "opening_balance": 100000
    }
    response = requests.post(f"{BASE_URL}/api/treasury", json=account_data, headers=auth_headers)
    assert response.status_code == 200, f"Failed to create treasury account: {response.text}"
    return response.json()


class TestLoggingSystem:
    """Tests for the logging system"""
    
    def test_logs_endpoint_accessible(self, auth_headers):
        """Test GET /api/logs is accessible"""
        response = requests.get(f"{BASE_URL}/api/logs", headers=auth_headers)
        assert response.status_code == 200, f"GET /api/logs failed: {response.text}"
        data = response.json()
        assert "logs" in data, "Response missing 'logs' field"
        assert "total" in data, "Response missing 'total' field"
        print(f"✓ GET /api/logs accessible - Total logs: {data['total']}")
    
    def test_logs_stats_endpoint(self, auth_headers):
        """Test GET /api/logs/stats returns stats with module breakdown"""
        response = requests.get(f"{BASE_URL}/api/logs/stats", headers=auth_headers)
        assert response.status_code == 200, f"GET /api/logs/stats failed: {response.text}"
        data = response.json()
        
        # Check required fields
        assert "total_logs" in data, "Response missing 'total_logs'"
        assert "today_logs" in data, "Response missing 'today_logs'"
        assert "by_type" in data, "Response missing 'by_type' (type breakdown)"
        
        print(f"✓ GET /api/logs/stats - Total: {data['total_logs']}, Today: {data['today_logs']}")
        if data.get("by_type"):
            print(f"  By type: {data['by_type']}")
        if data.get("by_module"):
            print(f"  By module: {data['by_module']}")
    
    def test_transaction_creates_activity_log(self, auth_headers, test_client, test_treasury_account):
        """Test POST /api/transactions creates both transaction AND activity log"""
        unique_ref = f"TX_LOG_TEST_{uuid.uuid4().hex[:8]}"
        
        # Create a transaction
        form_data = {
            "client_id": test_client["client_id"],
            "transaction_type": "deposit",
            "amount": "1500",
            "currency": "USD",
            "destination_type": "treasury",
            "destination_account_id": test_treasury_account["account_id"],
            "description": "Log test transaction",
            "reference": unique_ref
        }
        
        response = requests.post(f"{BASE_URL}/api/transactions", data=form_data, headers=auth_headers)
        assert response.status_code == 200, f"Failed to create transaction: {response.text}"
        transaction = response.json()
        print(f"✓ Created transaction: {transaction.get('transaction_id')} with ref: {unique_ref}")
        
        # Now check that a log entry was created in the 'transactions' module
        import time
        time.sleep(0.5)  # Small delay for async log creation
        
        logs_response = requests.get(
            f"{BASE_URL}/api/logs?module=transactions&limit=20", 
            headers=auth_headers
        )
        assert logs_response.status_code == 200, f"GET /api/logs?module=transactions failed: {logs_response.text}"
        logs_data = logs_response.json()
        
        # Should have at least one transaction log now
        assert logs_data["total"] > 0, "No transaction logs found - log_activity was NOT called!"
        
        # Check if we can find our specific transaction log
        found_log = False
        for log in logs_data["logs"]:
            if log.get("module") == "transactions":
                found_log = True
                print(f"  Found transaction log: action={log.get('action')}, desc={log.get('description')}")
                break
        
        assert found_log, "No logs with module='transactions' found!"
        print(f"✓ Transaction log created - Total transaction logs: {logs_data['total']}")
        
        return transaction
    
    def test_logs_filter_by_transactions_module(self, auth_headers):
        """Test GET /api/logs?module=transactions returns transaction logs"""
        response = requests.get(f"{BASE_URL}/api/logs?module=transactions", headers=auth_headers)
        assert response.status_code == 200, f"GET /api/logs?module=transactions failed: {response.text}"
        data = response.json()
        
        print(f"✓ Transaction logs filter - Found {data['total']} logs")
        
        # All returned logs should be from transactions module
        for log in data["logs"]:
            assert log.get("module") == "transactions", f"Log has wrong module: {log.get('module')}"
        
        if data["logs"]:
            sample = data["logs"][0]
            print(f"  Sample log: action={sample.get('action')}, desc={sample.get('description')[:50] if sample.get('description') else 'N/A'}")
    
    def test_logs_filter_by_clients_module(self, auth_headers):
        """Test GET /api/logs?module=clients returns client logs"""
        # First create a client to ensure there's a log
        unique_id = uuid.uuid4().hex[:8]
        client_data = {
            "first_name": f"ClientLogTest_{unique_id}",
            "last_name": "TestUser",
            "email": f"clientlogtest_{unique_id}@test.com"
        }
        create_response = requests.post(f"{BASE_URL}/api/clients", json=client_data, headers=auth_headers)
        assert create_response.status_code == 200, f"Failed to create client: {create_response.text}"
        
        import time
        time.sleep(0.5)  # Small delay for async log creation
        
        # Now check logs
        response = requests.get(f"{BASE_URL}/api/logs?module=clients", headers=auth_headers)
        assert response.status_code == 200, f"GET /api/logs?module=clients failed: {response.text}"
        data = response.json()
        
        print(f"✓ Client logs filter - Found {data['total']} logs")
        
        # All returned logs should be from clients module
        for log in data["logs"]:
            assert log.get("module") == "clients", f"Log has wrong module: {log.get('module')}"
        
        if data["logs"]:
            sample = data["logs"][0]
            print(f"  Sample log: action={sample.get('action')}, desc={sample.get('description')[:50] if sample.get('description') else 'N/A'}")
    
    def test_logs_returns_multiple_modules(self, auth_headers):
        """Test GET /api/logs (all) returns logs from multiple modules"""
        response = requests.get(f"{BASE_URL}/api/logs?limit=100", headers=auth_headers)
        assert response.status_code == 200, f"GET /api/logs failed: {response.text}"
        data = response.json()
        
        # Collect unique modules
        modules = set()
        for log in data["logs"]:
            if log.get("module"):
                modules.add(log["module"])
        
        print(f"✓ All logs query - Found {data['total']} logs across modules: {modules}")
        
        # Should have more than one module type
        assert len(modules) >= 1, "Expected logs from at least one module"
    
    def test_auth_logs_exist(self, auth_headers):
        """Test that auth logs are being created (from login)"""
        response = requests.get(f"{BASE_URL}/api/logs?log_type=auth&limit=20", headers=auth_headers)
        assert response.status_code == 200, f"GET /api/logs?log_type=auth failed: {response.text}"
        data = response.json()
        
        print(f"✓ Auth logs - Found {data['total']} auth logs")
        
        if data["logs"]:
            sample = data["logs"][0]
            print(f"  Sample: action={sample.get('action')}, module={sample.get('module')}")


class TestClientLogging:
    """Test client CRUD creates logs"""
    
    def test_create_client_creates_log(self, auth_headers):
        """Test creating a client generates a log entry"""
        unique_id = uuid.uuid4().hex[:8]
        client_data = {
            "first_name": f"CreateLogTest_{unique_id}",
            "last_name": "TestUser",
            "email": f"createlogtest_{unique_id}@test.com"
        }
        
        # Create client
        response = requests.post(f"{BASE_URL}/api/clients", json=client_data, headers=auth_headers)
        assert response.status_code == 200, f"Failed to create client: {response.text}"
        client = response.json()
        
        import time
        time.sleep(0.5)
        
        # Check logs
        logs_response = requests.get(
            f"{BASE_URL}/api/logs?module=clients&action=create&limit=10",
            headers=auth_headers
        )
        assert logs_response.status_code == 200
        logs_data = logs_response.json()
        
        assert logs_data["total"] > 0, "No 'create' logs found for clients module"
        print(f"✓ Create client generates log - Found {logs_data['total']} create logs in clients module")
    
    def test_update_client_creates_log(self, auth_headers):
        """Test updating a client generates a log entry"""
        # First create a client
        unique_id = uuid.uuid4().hex[:8]
        client_data = {
            "first_name": f"UpdateLogTest_{unique_id}",
            "last_name": "TestUser",
            "email": f"updatelogtest_{unique_id}@test.com"
        }
        
        create_response = requests.post(f"{BASE_URL}/api/clients", json=client_data, headers=auth_headers)
        assert create_response.status_code == 200
        client = create_response.json()
        
        # Update client
        update_data = {"first_name": f"UpdatedName_{unique_id}"}
        update_response = requests.put(
            f"{BASE_URL}/api/clients/{client['client_id']}", 
            json=update_data, 
            headers=auth_headers
        )
        assert update_response.status_code == 200, f"Failed to update client: {update_response.text}"
        
        import time
        time.sleep(0.5)
        
        # Check logs for edit action
        logs_response = requests.get(
            f"{BASE_URL}/api/logs?module=clients&action=edit&limit=10",
            headers=auth_headers
        )
        assert logs_response.status_code == 200
        logs_data = logs_response.json()
        
        assert logs_data["total"] > 0, "No 'edit' logs found for clients module"
        print(f"✓ Update client generates log - Found {logs_data['total']} edit logs in clients module")


class TestTreasuryLogging:
    """Test treasury operations create logs"""
    
    def test_create_treasury_creates_log(self, auth_headers):
        """Test creating a treasury account generates a log"""
        unique_id = uuid.uuid4().hex[:8]
        account_data = {
            "account_name": f"TreasuryLogTest_{unique_id}",
            "account_type": "bank",
            "bank_name": "Log Test Bank",
            "currency": "USD",
            "opening_balance": 5000
        }
        
        response = requests.post(f"{BASE_URL}/api/treasury", json=account_data, headers=auth_headers)
        assert response.status_code == 200, f"Failed to create treasury: {response.text}"
        
        import time
        time.sleep(0.5)
        
        # Check logs
        logs_response = requests.get(
            f"{BASE_URL}/api/logs?module=treasury&action=create&limit=10",
            headers=auth_headers
        )
        assert logs_response.status_code == 200
        logs_data = logs_response.json()
        
        assert logs_data["total"] > 0, "No 'create' logs found for treasury module"
        print(f"✓ Create treasury generates log - Found {logs_data['total']} create logs in treasury module")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
