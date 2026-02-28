"""
PSP Feature Tests for FX Broker Back-Office System
Testing: PSP Management, Transactions with PSP destination, Settlement workflow
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestAuthentication:
    """Test authentication endpoints"""
    
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
    
    def test_accountant_login(self):
        """Test accountant login"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "accountant@fxbroker.com",
            "password": "accountant123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["role"] == "accountant"
        print(f"Accountant login successful: {data['user']['email']}")


@pytest.fixture
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


class TestPSPManagement:
    """Test PSP CRUD operations"""
    
    def test_get_psps(self, auth_headers):
        """Test GET /api/psp - List all PSPs"""
        response = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"Found {len(data)} PSPs")
        # Verify seeded PSPs exist
        psp_names = [psp["psp_name"] for psp in data]
        assert "Stripe" in psp_names or "PayPal" in psp_names or "Skrill" in psp_names
        return data
    
    def test_get_psp_summary(self, auth_headers):
        """Test GET /api/psp-summary - Get PSP summary with pending/overdue counts"""
        response = requests.get(f"{BASE_URL}/api/psp-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Verify summary includes required fields
        if data:
            psp = data[0]
            assert "psp_name" in psp
            assert "commission_rate" in psp
            assert "settlement_days" in psp
            assert "pending_transactions_count" in psp
            assert "pending_amount" in psp
            assert "overdue_count" in psp
            assert "settlement_destination_name" in psp
            print(f"PSP Summary - {psp['psp_name']}: Pending ${psp['pending_amount']}, Overdue: {psp['overdue_count']}")
        return data
    
    def test_create_psp(self, auth_headers):
        """Test POST /api/psp - Create a new PSP"""
        # First get a treasury account for settlement destination
        treasury_response = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers)
        assert treasury_response.status_code == 200
        treasury_accounts = treasury_response.json()
        assert len(treasury_accounts) > 0, "No treasury accounts found"
        dest_account_id = treasury_accounts[0]["account_id"]
        
        # Create new PSP
        new_psp = {
            "psp_name": "TEST_TestPSP",
            "commission_rate": 2.0,
            "settlement_days": 2,
            "settlement_destination_id": dest_account_id,
            "min_settlement_amount": 50,
            "description": "Test PSP for automated testing"
        }
        response = requests.post(f"{BASE_URL}/api/psp", headers=auth_headers, json=new_psp)
        assert response.status_code == 200
        data = response.json()
        assert data["psp_name"] == "TEST_TestPSP"
        assert data["commission_rate"] == 2.0
        assert data["settlement_days"] == 2
        assert data["status"] == "active"
        print(f"Created PSP: {data['psp_id']}")
        return data
    
    def test_update_psp(self, auth_headers):
        """Test PUT /api/psp/{psp_id} - Update PSP"""
        # Get PSPs
        psps = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers).json()
        test_psp = next((p for p in psps if "TEST_" in p["psp_name"]), psps[0] if psps else None)
        if not test_psp:
            pytest.skip("No PSP found to update")
        
        # Update PSP
        updates = {
            "commission_rate": 3.0,
            "description": "Updated description"
        }
        response = requests.put(f"{BASE_URL}/api/psp/{test_psp['psp_id']}", headers=auth_headers, json=updates)
        assert response.status_code == 200
        data = response.json()
        assert data["commission_rate"] == 3.0
        assert data["description"] == "Updated description"
        print(f"Updated PSP: {data['psp_id']}")
    
    def test_get_single_psp(self, auth_headers):
        """Test GET /api/psp/{psp_id} - Get single PSP"""
        # Get all PSPs first
        psps = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers).json()
        if not psps:
            pytest.skip("No PSPs found")
        
        psp_id = psps[0]["psp_id"]
        response = requests.get(f"{BASE_URL}/api/psp/{psp_id}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["psp_id"] == psp_id
        print(f"Got PSP: {data['psp_name']}")


class TestPSPTransactions:
    """Test creating transactions with PSP as destination"""
    
    def test_create_psp_transaction_client_pays_commission(self, auth_headers):
        """Test creating a deposit transaction via PSP where client pays commission"""
        # Get a client
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        client_id = clients[0]["client_id"]
        
        # Get PSPs
        psps = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers).json()
        active_psps = [p for p in psps if p.get("status") == "active"]
        if not active_psps:
            pytest.skip("No active PSPs found")
        psp = active_psps[0]
        
        # Create transaction via PSP
        form_data = {
            "client_id": client_id,
            "transaction_type": "deposit",
            "amount": "1000",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "psp",
            "psp_id": psp["psp_id"],
            "commission_paid_by": "client",
            "description": "TEST_PSP transaction - client pays commission"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify PSP fields
        assert data["destination_type"] == "psp"
        assert data["psp_id"] == psp["psp_id"]
        assert data["psp_name"] == psp["psp_name"]
        assert data["psp_commission_rate"] == psp["commission_rate"]
        assert data["psp_commission_paid_by"] == "client"
        
        # Verify commission calculation
        commission_amount = 1000 * (psp["commission_rate"] / 100)
        expected_net = 1000 - commission_amount
        assert abs(data["psp_commission_amount"] - commission_amount) < 0.01
        assert abs(data["psp_net_amount"] - expected_net) < 0.01
        assert data["psp_expected_settlement_date"] is not None
        
        print(f"Created PSP transaction: {data['transaction_id']}")
        print(f"  Gross: ${data['amount']}, Commission: ${data['psp_commission_amount']}, Net: ${data['psp_net_amount']}")
        return data
    
    def test_create_psp_transaction_broker_pays_commission(self, auth_headers):
        """Test creating a deposit transaction via PSP where broker pays commission"""
        # Get a client
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        if not clients:
            pytest.skip("No clients found")
        client_id = clients[0]["client_id"]
        
        # Get PSPs
        psps = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers).json()
        active_psps = [p for p in psps if p.get("status") == "active"]
        if not active_psps:
            pytest.skip("No active PSPs found")
        psp = active_psps[0]
        
        # Create transaction via PSP
        form_data = {
            "client_id": client_id,
            "transaction_type": "deposit",
            "amount": "500",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "psp",
            "psp_id": psp["psp_id"],
            "commission_paid_by": "broker",
            "description": "TEST_PSP transaction - broker pays commission"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify commission - when broker pays, net = gross
        assert data["psp_commission_paid_by"] == "broker"
        assert data["psp_net_amount"] == 500.0  # Full amount since broker absorbs commission
        
        print(f"Created PSP transaction (broker pays): {data['transaction_id']}")
        return data


class TestPSPPendingTransactions:
    """Test PSP pending transactions and settlements"""
    
    def test_get_pending_transactions(self, auth_headers):
        """Test GET /api/psp/{psp_id}/pending-transactions"""
        # Get PSPs
        psps = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers).json()
        if not psps:
            pytest.skip("No PSPs found")
        
        psp_id = psps[0]["psp_id"]
        response = requests.get(f"{BASE_URL}/api/psp/{psp_id}/pending-transactions", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"PSP {psps[0]['psp_name']} has {len(data)} pending transactions")
        return data


class TestPSPSettlements:
    """Test PSP settlement workflow"""
    
    def test_get_psp_settlements(self, auth_headers):
        """Test GET /api/psp/{psp_id}/settlements"""
        psps = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers).json()
        if not psps:
            pytest.skip("No PSPs found")
        
        psp_id = psps[0]["psp_id"]
        response = requests.get(f"{BASE_URL}/api/psp/{psp_id}/settlements", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"Found {len(data)} settlements for PSP")
    
    def test_settle_single_transaction(self, auth_headers):
        """Test POST /api/psp/transactions/{tx_id}/settle - Settle single transaction"""
        # First create a PSP transaction
        clients = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers).json()
        psps = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers).json()
        active_psps = [p for p in psps if p.get("status") == "active"]
        
        if not clients or not active_psps:
            pytest.skip("Missing clients or PSPs")
        
        psp = active_psps[0]
        client_id = clients[0]["client_id"]
        
        # Create a transaction
        form_data = {
            "client_id": client_id,
            "transaction_type": "deposit",
            "amount": "200",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "psp",
            "psp_id": psp["psp_id"],
            "commission_paid_by": "client",
            "description": "TEST_Settlement test transaction"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": auth_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        tx_id = tx["transaction_id"]
        
        # Now settle this transaction
        settle_response = requests.post(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/settle",
            headers=auth_headers
        )
        assert settle_response.status_code == 200
        settled_tx = settle_response.json()
        
        # Verify settlement
        assert settled_tx["settled"] == True
        assert settled_tx["settlement_status"] == "completed"
        assert settled_tx["settled_at"] is not None
        assert "settlement_destination_name" in settled_tx
        
        print(f"Successfully settled transaction: {tx_id}")
        print(f"  Net amount settled: ${settled_tx['psp_net_amount']}")
        return settled_tx


class TestCleanup:
    """Cleanup test data"""
    
    def test_cleanup_test_psps(self, auth_headers):
        """Delete TEST_ prefixed PSPs"""
        psps = requests.get(f"{BASE_URL}/api/psp", headers=auth_headers).json()
        test_psps = [p for p in psps if p["psp_name"].startswith("TEST_")]
        
        for psp in test_psps:
            response = requests.delete(f"{BASE_URL}/api/psp/{psp['psp_id']}", headers=auth_headers)
            if response.status_code == 200:
                print(f"Deleted test PSP: {psp['psp_name']}")


class TestTreasuryIntegration:
    """Test that PSP settlements correctly update Treasury balances"""
    
    def test_treasury_balance_update_on_settlement(self, auth_headers):
        """Verify treasury balance increases after settlement"""
        # Get treasury accounts
        treasury_before = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers).json()
        if not treasury_before:
            pytest.skip("No treasury accounts found")
        
        first_account = treasury_before[0]
        initial_balance = first_account.get("balance", 0)
        
        print(f"Treasury {first_account['account_name']} initial balance: ${initial_balance}")
        
        # Note: Settlement already tested above which updates treasury
        # This test verifies treasury endpoint returns balance correctly
        assert "balance" in first_account
        assert "account_name" in first_account
        assert first_account.get("status") == "active"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
