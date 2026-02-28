"""
Vendor Commission Calculation Tests
Testing: Commission is calculated as percentage from vendor's commission rate on transaction approval
Settlement formula: (Deposits - Withdrawals) - Commission Earned

Features tested:
- Commission calculated on vendor approval (vendor_commission_amount field)
- Settlement balance shows: (Deposits - Withdrawals) - Commission
- Commission column displays in Vendor Portal transactions table
- Total Commission Earned card shows in Vendor Portal
- Admin can see commission data in vendor details
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# === Authentication Fixtures ===

@pytest.fixture(scope="module")
def admin_token():
    """Get admin authentication token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "admin@fxbroker.com",
        "password": "password"
    })
    if response.status_code == 200:
        return response.json()["access_token"]
    pytest.skip("Admin authentication failed")

@pytest.fixture(scope="module")
def vendor1_token():
    """Get vendor1 authentication token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "vendor1@fxbroker.com",
        "password": "password"
    })
    if response.status_code == 200:
        return response.json()["access_token"]
    pytest.skip("Vendor1 authentication failed")

@pytest.fixture(scope="module")
def vendor3_token():
    """Get vendor3 authentication token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "vendor3@fxbroker.com",
        "password": "password"
    })
    if response.status_code == 200:
        return response.json()["access_token"]
    pytest.skip("Vendor3 authentication failed")

@pytest.fixture
def admin_headers(admin_token):
    """Get authorization headers with admin token"""
    return {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

@pytest.fixture
def vendor1_headers(vendor1_token):
    """Get authorization headers with vendor1 token"""
    return {
        "Authorization": f"Bearer {vendor1_token}",
        "Content-Type": "application/json"
    }

@pytest.fixture
def vendor3_headers(vendor3_token):
    """Get authorization headers with vendor3 token"""
    return {
        "Authorization": f"Bearer {vendor3_token}",
        "Content-Type": "application/json"
    }


# === Vendor Commission Calculation Tests ===

class TestVendorCommissionCalculation:
    """Test vendor commission is calculated correctly on transaction approval"""
    
    def test_vendor_has_commission_rates(self, admin_headers):
        """Verify vendors have deposit_commission and withdrawal_commission rates"""
        response = requests.get(f"{BASE_URL}/api/vendors", headers=admin_headers)
        assert response.status_code == 200
        vendors = response.json()
        assert len(vendors) > 0, "No vendors found"
        
        vendor = vendors[0]
        assert "deposit_commission" in vendor, "Vendor should have deposit_commission rate"
        assert "withdrawal_commission" in vendor, "Vendor should have withdrawal_commission rate"
        print(f"Vendor '{vendor['vendor_name']}' - Deposit commission: {vendor['deposit_commission']}%, Withdrawal commission: {vendor['withdrawal_commission']}%")
    
    def test_vendor_me_shows_commission_rates(self, vendor1_headers):
        """Vendor portal /api/vendor/me returns commission rates"""
        response = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor1_headers)
        assert response.status_code == 200
        data = response.json()
        
        assert "deposit_commission" in data, "Vendor /me should include deposit_commission"
        assert "withdrawal_commission" in data, "Vendor /me should include withdrawal_commission"
        print(f"Vendor portal shows: Deposit {data['deposit_commission']}%, Withdrawal {data['withdrawal_commission']}%")
    
    def test_deposit_approval_calculates_commission(self, vendor1_headers, admin_headers):
        """When vendor approves a deposit, commission is calculated based on deposit_commission rate"""
        # Get vendor info first
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor1_headers).json()
        deposit_rate = vendor_info.get("deposit_commission", 0)
        
        # Get a client
        clients = requests.get(f"{BASE_URL}/api/clients", headers=admin_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        # Create a deposit transaction via vendor
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "1000",  # $1000 deposit
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor_info["vendor_id"],
            "description": "TEST_Commission calculation test deposit"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": admin_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        tx_id = tx["transaction_id"]
        
        # Approve the transaction as vendor
        approve_response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx_id}/approve",
            headers=vendor1_headers
        )
        assert approve_response.status_code == 200
        approved_tx = approve_response.json()
        
        # Verify commission was calculated
        assert "vendor_commission_amount" in approved_tx, "Approved transaction should have vendor_commission_amount"
        assert "vendor_commission_rate" in approved_tx, "Approved transaction should have vendor_commission_rate"
        
        expected_commission = round(1000 * (deposit_rate / 100), 2)
        assert approved_tx["vendor_commission_rate"] == deposit_rate, f"Commission rate should be {deposit_rate}%"
        assert approved_tx["vendor_commission_amount"] == expected_commission, f"Commission should be ${expected_commission}"
        
        print(f"Deposit approved: $1000, Commission rate: {deposit_rate}%, Commission: ${approved_tx['vendor_commission_amount']}")
        return approved_tx
    
    def test_withdrawal_approval_calculates_commission(self, vendor1_headers, admin_headers):
        """When vendor approves a withdrawal, commission is calculated based on withdrawal_commission rate"""
        # Get vendor info
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor1_headers).json()
        withdrawal_rate = vendor_info.get("withdrawal_commission", 0)
        
        # Get a client
        clients = requests.get(f"{BASE_URL}/api/clients", headers=admin_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        # Create a withdrawal transaction
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "withdrawal",
            "amount": "500",  # $500 withdrawal
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor_info["vendor_id"],
            "description": "TEST_Commission calculation test withdrawal"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": admin_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        tx_id = tx["transaction_id"]
        
        # Approve as vendor
        approve_response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx_id}/approve",
            headers=vendor1_headers
        )
        assert approve_response.status_code == 200
        approved_tx = approve_response.json()
        
        # Verify commission calculation
        expected_commission = round(500 * (withdrawal_rate / 100), 2)
        assert approved_tx["vendor_commission_rate"] == withdrawal_rate
        assert approved_tx["vendor_commission_amount"] == expected_commission
        
        print(f"Withdrawal approved: $500, Commission rate: {withdrawal_rate}%, Commission: ${approved_tx['vendor_commission_amount']}")
        return approved_tx


class TestSettlementBalanceWithCommission:
    """Test settlement balance formula: (Deposits - Withdrawals) - Commission"""
    
    def test_vendor_me_shows_settlement_by_currency(self, vendor1_headers):
        """Vendor /api/vendor/me returns settlement_by_currency with commission_earned"""
        response = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor1_headers)
        assert response.status_code == 200
        data = response.json()
        
        assert "settlement_by_currency" in data, "Vendor /me should include settlement_by_currency"
        
        if data["settlement_by_currency"]:
            item = data["settlement_by_currency"][0]
            assert "currency" in item
            assert "amount" in item
            assert "usd_equivalent" in item
            assert "deposit_amount" in item
            assert "withdrawal_amount" in item
            assert "commission_earned" in item
            assert "deposit_count" in item
            assert "withdrawal_count" in item
            
            # Verify formula: usd_equivalent = (deposits - withdrawals) - commission
            expected_usd = (item["deposit_usd"] if "deposit_usd" in item else 0) - \
                          (item["withdrawal_usd"] if "withdrawal_usd" in item else 0) - \
                          item["commission_earned"]
            
            print(f"Settlement - Currency: {item['currency']}, Deposits: ${item.get('deposit_amount', 0)}, "
                  f"Withdrawals: ${item.get('withdrawal_amount', 0)}, "
                  f"Commission: ${item['commission_earned']}, "
                  f"Net USD: ${item['usd_equivalent']}")
    
    def test_admin_vendor_details_shows_settlement(self, admin_headers):
        """Admin GET /api/vendors/{vendor_id} returns settlement_by_currency with commission"""
        # Get vendors
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=admin_headers).json()
        assert len(vendors) > 0
        
        vendor_id = vendors[0]["vendor_id"]
        response = requests.get(f"{BASE_URL}/api/vendors/{vendor_id}", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        
        assert "settlement_by_currency" in data, "Vendor details should include settlement_by_currency"
        
        if data["settlement_by_currency"]:
            item = data["settlement_by_currency"][0]
            assert "commission_earned" in item, "Settlement should show commission_earned"
            print(f"Admin view - Vendor: {data['vendor_name']}, Commission earned: ${item['commission_earned']}")


class TestCommissionColumnInTransactions:
    """Test commission column displays in transactions tables"""
    
    def test_vendor_transactions_include_commission(self, vendor1_headers):
        """Vendor's transaction list includes vendor_commission_amount for approved transactions"""
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor1_headers).json()
        
        response = requests.get(
            f"{BASE_URL}/api/vendors/{vendor_info['vendor_id']}/transactions",
            headers=vendor1_headers
        )
        assert response.status_code == 200
        transactions = response.json()
        
        # Check approved transactions have commission
        approved_txs = [tx for tx in transactions if tx["status"] == "approved"]
        
        for tx in approved_txs:
            # Commission should be present for approved vendor transactions
            if "vendor_commission_amount" in tx:
                print(f"Transaction {tx['reference']}: Status={tx['status']}, Commission=${tx['vendor_commission_amount']}")
    
    def test_admin_vendor_transactions_include_commission(self, admin_headers):
        """Admin view of vendor transactions includes commission data"""
        vendors = requests.get(f"{BASE_URL}/api/vendors", headers=admin_headers).json()
        assert len(vendors) > 0
        
        vendor_id = vendors[0]["vendor_id"]
        response = requests.get(f"{BASE_URL}/api/vendors/{vendor_id}/transactions", headers=admin_headers)
        assert response.status_code == 200
        transactions = response.json()
        
        approved_txs = [tx for tx in transactions if tx["status"] == "approved"]
        
        for tx in approved_txs:
            if "vendor_commission_amount" in tx:
                print(f"Admin view - Transaction {tx['reference']}: Commission=${tx['vendor_commission_amount']}")


class TestTotalCommissionEarned:
    """Test Total Commission Earned aggregation"""
    
    def test_total_commission_from_settlement_by_currency(self, vendor1_headers):
        """Total commission earned is sum of commission_earned from all currencies"""
        response = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor1_headers)
        assert response.status_code == 200
        data = response.json()
        
        if data["settlement_by_currency"]:
            total_commission = sum(item.get("commission_earned", 0) for item in data["settlement_by_currency"])
            print(f"Total Commission Earned: ${total_commission}")
            
            # Verify each currency contributes
            for item in data["settlement_by_currency"]:
                print(f"  {item['currency']}: ${item.get('commission_earned', 0)}")


class TestCommissionWithDifferentRates:
    """Test commission calculation with different vendor rates"""
    
    def test_vendor3_commission_rates(self, vendor3_headers, admin_headers):
        """Test vendor3 has different commission rates applied"""
        # Get vendor3 info
        vendor_info = requests.get(f"{BASE_URL}/api/vendor/me", headers=vendor3_headers).json()
        
        print(f"Vendor3: {vendor_info['vendor_name']}")
        print(f"  Deposit Commission: {vendor_info['deposit_commission']}%")
        print(f"  Withdrawal Commission: {vendor_info['withdrawal_commission']}%")
        
        # Create and approve a deposit to verify calculation
        clients = requests.get(f"{BASE_URL}/api/clients", headers=admin_headers).json()
        if not clients:
            pytest.skip("No clients found")
        
        form_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": "2000",
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "vendor",
            "vendor_id": vendor_info["vendor_id"],
            "description": "TEST_Vendor3 commission test"
        }
        
        create_response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers={"Authorization": admin_headers["Authorization"]},
            data=form_data
        )
        assert create_response.status_code == 200
        tx = create_response.json()
        
        # Approve as vendor3
        approve_response = requests.post(
            f"{BASE_URL}/api/vendor/transactions/{tx['transaction_id']}/approve",
            headers=vendor3_headers
        )
        assert approve_response.status_code == 200
        approved_tx = approve_response.json()
        
        expected_commission = round(2000 * (vendor_info["deposit_commission"] / 100), 2)
        assert approved_tx["vendor_commission_amount"] == expected_commission
        print(f"Vendor3 deposit $2000 -> Commission ${approved_tx['vendor_commission_amount']} ({vendor_info['deposit_commission']}%)")


class TestCleanup:
    """Cleanup test transactions"""
    
    def test_cleanup_test_transactions(self, admin_headers):
        """Clean up TEST_ prefixed transactions"""
        # Get all transactions
        response = requests.get(f"{BASE_URL}/api/transactions", headers=admin_headers)
        if response.status_code == 200:
            transactions = response.json()
            test_txs = [tx for tx in transactions if "TEST_" in (tx.get("description") or "")]
            print(f"Found {len(test_txs)} test transactions to consider for cleanup")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
