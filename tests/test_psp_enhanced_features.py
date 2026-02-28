"""
Test PSP Enhanced Features:
1. PSP settings: chargeback_rate and holding_days fields
2. Record Charges - chargeback_amount and extra_charges per transaction
3. Holding days and release date calculation
4. Record Payment Received - updates treasury balance
5. Net settlement calculation: Gross - Commission - Chargeback - Extra Charges
"""

import pytest
import requests
import os
import uuid
from datetime import datetime, timedelta

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
TEST_EMAIL = "admin@fxbroker.com"
TEST_PASSWORD = "password"

# Test data IDs from review request
TEST_PSP_ID = "psp_1f22117d21a5"  # PayPal with 10% commission, 3% chargeback, 2 days holding
TEST_TREASURY_ID = "treasury_d812e38f2a7a"  # ENBD account
TEST_CLIENT_ID = "client_e9792d8531d1"

@pytest.fixture(scope="module")
def auth_token():
    """Get authentication token"""
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    return response.json()["access_token"]

@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Get headers with auth token"""
    return {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

@pytest.fixture(scope="module")
def form_headers(auth_token):
    """Get headers for form data requests (no content-type, let requests set it)"""
    return {
        "Authorization": f"Bearer {auth_token}"
    }


class TestPSPSettings:
    """Test PSP settings with chargeback_rate and holding_days"""
    
    def test_get_psp_has_chargeback_and_holding_fields(self, auth_headers):
        """Verify PSP has chargeback_rate and holding_days fields"""
        response = requests.get(
            f"{BASE_URL}/api/psp/{TEST_PSP_ID}",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to get PSP: {response.text}"
        psp = response.json()
        
        # Verify required fields exist
        assert "chargeback_rate" in psp, "PSP missing chargeback_rate field"
        assert "holding_days" in psp, "PSP missing holding_days field"
        
        # Verify expected values (from test data: 3% chargeback, 2 days holding)
        assert psp["chargeback_rate"] == 3, f"Expected chargeback_rate=3, got {psp['chargeback_rate']}"
        assert psp["holding_days"] == 2, f"Expected holding_days=2, got {psp['holding_days']}"
        print(f"PSP settings verified: chargeback_rate={psp['chargeback_rate']}%, holding_days={psp['holding_days']}")
    
    def test_psp_summary_includes_new_fields(self, auth_headers):
        """PSP summary should include chargeback and holding info"""
        response = requests.get(
            f"{BASE_URL}/api/psp-summary",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to get PSP summary: {response.text}"
        psps = response.json()
        
        # Find test PSP
        test_psp = next((p for p in psps if p["psp_id"] == TEST_PSP_ID), None)
        assert test_psp, "Test PSP not found in summary"
        
        # Verify fields
        assert "chargeback_rate" in test_psp, "Summary missing chargeback_rate"
        assert "holding_days" in test_psp, "Summary missing holding_days"
        print(f"PSP summary includes chargeback_rate={test_psp['chargeback_rate']}%, holding_days={test_psp['holding_days']}")
    
    def test_create_psp_with_chargeback_and_holding(self, auth_headers):
        """Create new PSP with chargeback_rate and holding_days"""
        psp_data = {
            "psp_name": f"TEST_PSP_{uuid.uuid4().hex[:8]}",
            "commission_rate": 2.5,
            "chargeback_rate": 1.5,  # 1.5% chargeback reserve
            "holding_days": 5,       # 5 days holding
            "settlement_days": 2,
            "settlement_destination_id": TEST_TREASURY_ID,
            "min_settlement_amount": 100,
            "description": "Test PSP with chargeback and holding"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/psp",
            headers=auth_headers,
            json=psp_data
        )
        assert response.status_code == 200, f"Failed to create PSP: {response.text}"
        psp = response.json()
        
        # Verify all fields
        assert psp["chargeback_rate"] == 1.5, f"chargeback_rate mismatch: {psp['chargeback_rate']}"
        assert psp["holding_days"] == 5, f"holding_days mismatch: {psp['holding_days']}"
        assert psp["commission_rate"] == 2.5
        print(f"Created PSP with chargeback_rate={psp['chargeback_rate']}%, holding_days={psp['holding_days']}")
        
        # Cleanup
        requests.delete(f"{BASE_URL}/api/psp/{psp['psp_id']}", headers=auth_headers)
    
    def test_update_psp_chargeback_and_holding(self, auth_headers):
        """Update PSP chargeback_rate and holding_days"""
        # First create a test PSP
        psp_data = {
            "psp_name": f"TEST_UPDATE_{uuid.uuid4().hex[:8]}",
            "commission_rate": 3.0,
            "chargeback_rate": 2.0,
            "holding_days": 3,
            "settlement_days": 1,
            "settlement_destination_id": TEST_TREASURY_ID
        }
        
        create_resp = requests.post(f"{BASE_URL}/api/psp", headers=auth_headers, json=psp_data)
        assert create_resp.status_code == 200
        psp_id = create_resp.json()["psp_id"]
        
        # Update chargeback and holding
        update_data = {
            "chargeback_rate": 4.0,
            "holding_days": 7
        }
        
        update_resp = requests.put(
            f"{BASE_URL}/api/psp/{psp_id}",
            headers=auth_headers,
            json=update_data
        )
        assert update_resp.status_code == 200, f"Update failed: {update_resp.text}"
        updated = update_resp.json()
        
        assert updated["chargeback_rate"] == 4.0
        assert updated["holding_days"] == 7
        print(f"Updated PSP: chargeback_rate=4.0%, holding_days=7")
        
        # Cleanup
        requests.delete(f"{BASE_URL}/api/psp/{psp_id}", headers=auth_headers)


class TestPSPTransactionCharges:
    """Test recording chargeback and extra charges on transactions"""
    
    def test_create_transaction_with_psp_holding_and_release_date(self, form_headers):
        """New PSP transactions should have holding_days and holding_release_date"""
        # Use form data for transaction creation
        tx_data = {
            "client_id": TEST_CLIENT_ID,
            "transaction_type": "deposit",
            "amount": "1000",
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": TEST_PSP_ID,
            "reference": f"TEST_HOLDING_{uuid.uuid4().hex[:8]}"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers=form_headers,
            data=tx_data
        )
        assert response.status_code == 200, f"Failed to create transaction: {response.text}"
        tx = response.json()
        
        # Verify holding fields from PSP (2 days holding)
        assert "psp_holding_days" in tx, "Transaction missing psp_holding_days"
        assert tx["psp_holding_days"] == 2, f"Expected holding_days=2, got {tx['psp_holding_days']}"
        
        assert "psp_holding_release_date" in tx, "Transaction missing psp_holding_release_date"
        assert tx["psp_holding_release_date"], "psp_holding_release_date should not be null"
        
        assert "psp_chargeback_rate" in tx, "Transaction missing psp_chargeback_rate"
        assert tx["psp_chargeback_rate"] == 3, f"Expected chargeback_rate=3, got {tx['psp_chargeback_rate']}"
        
        print(f"Transaction has holding_days={tx['psp_holding_days']}, release_date={tx['psp_holding_release_date']}")
        
        return tx["transaction_id"]
    
    def test_record_charges_on_transaction(self, auth_headers, form_headers):
        """Record chargeback and extra charges on a PSP transaction"""
        # First create a test transaction using form data
        tx_data = {
            "client_id": TEST_CLIENT_ID,
            "transaction_type": "deposit",
            "amount": "2000",
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": TEST_PSP_ID,
            "reference": f"TEST_CHARGES_{uuid.uuid4().hex[:8]}"
        }
        
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=form_headers, data=tx_data)
        assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
        tx_id = create_resp.json()["transaction_id"]
        commission = create_resp.json().get("psp_commission_amount", 200)  # 10% of 2000
        
        # Record charges using JSON
        charges_data = {
            "chargeback_amount": 50.00,
            "extra_charges": 25.00,
            "charges_description": "Chargeback + processing fees"
        }
        
        response = requests.put(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/charges",
            headers=auth_headers,
            json=charges_data
        )
        assert response.status_code == 200, f"Failed to record charges: {response.text}"
        updated_tx = response.json()
        
        # Verify charges stored
        assert updated_tx.get("psp_chargeback_amount") == 50.00
        assert updated_tx.get("psp_extra_charges") == 25.00
        assert updated_tx.get("psp_charges_description") == "Chargeback + processing fees"
        print(f"Recorded charges: chargeback=${updated_tx['psp_chargeback_amount']}, extra=${updated_tx['psp_extra_charges']}")
        
        # Verify net amount calculation: Gross - Commission - Chargeback - Extra
        # Gross=2000, Commission=10%=200, Chargeback=50, Extra=25
        # Net = 2000 - 200 - 50 - 25 = 1725
        expected_net = 2000 - 200 - 50 - 25
        assert updated_tx.get("psp_net_amount") == expected_net, f"Expected net={expected_net}, got {updated_tx.get('psp_net_amount')}"
        print(f"Net settlement verified: {expected_net}")
        
        return tx_id
    
    def test_cannot_update_charges_on_settled_transaction(self, auth_headers):
        """Should verify charges update works on pending transactions"""
        # Get pending transactions
        pending_resp = requests.get(
            f"{BASE_URL}/api/psp/{TEST_PSP_ID}/pending-transactions",
            headers=auth_headers
        )
        pending = pending_resp.json()
        
        if pending:
            # Get an existing pending transaction
            tx_id = pending[0]["transaction_id"]
            
            # Verify we can update charges on pending transaction
            charges_data = {
                "chargeback_amount": 10.00,
                "extra_charges": 5.00
            }
            
            response = requests.put(
                f"{BASE_URL}/api/psp/transactions/{tx_id}/charges",
                headers=auth_headers,
                json=charges_data
            )
            
            # Should work since it's not settled
            assert response.status_code == 200, f"Should be able to update charges: {response.text}"
            
            # Reset charges
            requests.put(
                f"{BASE_URL}/api/psp/transactions/{tx_id}/charges",
                headers=auth_headers,
                json={"chargeback_amount": 0, "extra_charges": 0}
            )
            print(f"Verified charges can be updated on pending transaction")


class TestRecordPaymentReceived:
    """Test record payment received functionality"""
    
    def test_record_payment_updates_treasury(self, auth_headers, form_headers):
        """Recording payment should update treasury balance"""
        # Create a test transaction
        tx_data = {
            "client_id": TEST_CLIENT_ID,
            "transaction_type": "deposit",
            "amount": "1500",
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": TEST_PSP_ID,
            "reference": f"TEST_PAYMENT_{uuid.uuid4().hex[:8]}"
        }
        
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=form_headers, data=tx_data)
        assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
        tx = create_resp.json()
        tx_id = tx["transaction_id"]
        
        # Get treasury balance before
        treasury_before = requests.get(
            f"{BASE_URL}/api/treasury/{TEST_TREASURY_ID}",
            headers=auth_headers
        ).json()
        balance_before = treasury_before["balance"]
        
        # Expected net: 1500 - 10% commission = 1350
        expected_net = 1500 - 150  # 10% of 1500
        
        # Record payment received
        response = requests.post(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/record-payment?destination_account_id={TEST_TREASURY_ID}&actual_amount_received={expected_net}",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Record payment failed: {response.text}"
        settled_tx = response.json()
        
        # Verify transaction marked as settled
        assert settled_tx.get("settled") == True, "Transaction should be settled"
        assert settled_tx.get("settlement_status") == "completed"
        assert settled_tx.get("psp_actual_amount_received") == expected_net
        print(f"Transaction settled with actual amount: ${expected_net}")
        
        # Verify treasury balance increased
        treasury_after = requests.get(
            f"{BASE_URL}/api/treasury/{TEST_TREASURY_ID}",
            headers=auth_headers
        ).json()
        balance_after = treasury_after["balance"]
        
        # Treasury balance should increase
        balance_increase = balance_after - balance_before
        assert balance_increase > 0, f"Treasury balance should increase, but diff={balance_increase}"
        print(f"Treasury balance increased by {balance_increase} (currency: {treasury_after['currency']})")
    
    def test_record_payment_with_variance(self, auth_headers, form_headers):
        """Record payment with variance (actual != expected)"""
        # Create a test transaction
        tx_data = {
            "client_id": TEST_CLIENT_ID,
            "transaction_type": "deposit",
            "amount": "1000",
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": TEST_PSP_ID,
            "reference": f"TEST_VARIANCE_{uuid.uuid4().hex[:8]}"
        }
        
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=form_headers, data=tx_data)
        assert create_resp.status_code == 200
        tx_id = create_resp.json()["transaction_id"]
        net_amount = create_resp.json().get("psp_net_amount", 900)  # Should be 1000 - 10% = 900
        
        # Record with different actual amount
        actual_received = 880  # $20 less than expected
        
        response = requests.post(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/record-payment?destination_account_id={TEST_TREASURY_ID}&actual_amount_received={actual_received}",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Record payment failed: {response.text}"
        tx = response.json()
        
        # Verify variance recorded
        assert tx.get("psp_actual_amount_received") == actual_received
        variance = tx.get("psp_settlement_variance")
        expected_variance = actual_received - net_amount
        assert variance == expected_variance, f"Expected variance={expected_variance}, got {variance}"
        print(f"Variance recorded: ${variance}")


class TestNetSettlementCalculation:
    """Test net settlement calculation: Gross - Commission - Chargeback - Extra Charges"""
    
    def test_net_calculation_with_all_deductions(self, auth_headers, form_headers):
        """Verify net = Gross - Commission - Chargeback - Extra"""
        # Create transaction
        tx_data = {
            "client_id": TEST_CLIENT_ID,
            "transaction_type": "deposit",
            "amount": "5000",
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": TEST_PSP_ID,
            "reference": f"TEST_NET_{uuid.uuid4().hex[:8]}"
        }
        
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=form_headers, data=tx_data)
        assert create_resp.status_code == 200
        tx_id = create_resp.json()["transaction_id"]
        commission = create_resp.json().get("psp_commission_amount", 500)  # 10% of 5000
        
        # Add charges
        charges_data = {
            "chargeback_amount": 100.00,
            "extra_charges": 50.00,
            "charges_description": "Chargeback + fees"
        }
        
        charges_resp = requests.put(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/charges",
            headers=auth_headers,
            json=charges_data
        )
        assert charges_resp.status_code == 200
        tx = charges_resp.json()
        
        # Calculate expected net
        gross = 5000
        expected_commission = 500  # 10%
        chargeback = 100
        extra = 50
        expected_net = gross - expected_commission - chargeback - extra
        
        actual_net = tx.get("psp_net_amount")
        assert actual_net == expected_net, f"Net mismatch: expected={expected_net}, got={actual_net}"
        
        # Verify total deductions
        total_deductions = tx.get("psp_total_deductions")
        expected_deductions = expected_commission + chargeback + extra
        assert total_deductions == expected_deductions, f"Deductions mismatch: expected={expected_deductions}, got={total_deductions}"
        
        print(f"Net settlement calculation verified:")
        print(f"  Gross: ${gross}")
        print(f"  Commission: -${expected_commission}")
        print(f"  Chargeback: -${chargeback}")
        print(f"  Extra: -${extra}")
        print(f"  Net: ${actual_net}")


class TestTreasuryTransactionRecord:
    """Test treasury transaction record created on payment"""
    
    def test_treasury_transaction_created_on_payment(self, auth_headers, form_headers):
        """Verify treasury transaction is created when payment is recorded"""
        # Create transaction
        tx_data = {
            "client_id": TEST_CLIENT_ID,
            "transaction_type": "deposit",
            "amount": "800",
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": TEST_PSP_ID,
            "reference": f"TEST_TREASURY_TX_{uuid.uuid4().hex[:8]}"
        }
        
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=form_headers, data=tx_data)
        assert create_resp.status_code == 200
        tx_id = create_resp.json()["transaction_id"]
        
        # Record payment
        actual_amount = 720  # 800 - 10% = 720
        response = requests.post(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/record-payment?destination_account_id={TEST_TREASURY_ID}&actual_amount_received={actual_amount}",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        # Check treasury history for this transaction
        history_resp = requests.get(
            f"{BASE_URL}/api/treasury/{TEST_TREASURY_ID}/history?limit=20",
            headers=auth_headers
        )
        assert history_resp.status_code == 200
        history = history_resp.json()
        
        # Find the treasury transaction for this PSP settlement
        psp_tx = None
        for h in history:
            if h.get("transaction_type") == "psp_settlement" and h.get("related_transaction_id") == tx_id:
                psp_tx = h
                break
        
        assert psp_tx, "Treasury transaction not found for PSP settlement"
        assert psp_tx["amount"] == actual_amount
        assert psp_tx["psp_id"] == TEST_PSP_ID
        print(f"Treasury transaction created: {psp_tx['treasury_transaction_id']}, amount=${psp_tx['amount']}")


class TestPendingTransactionFields:
    """Test pending transactions have correct holding and release date fields"""
    
    def test_pending_transactions_have_holding_fields(self, auth_headers):
        """Pending transactions should show holding days and release date"""
        response = requests.get(
            f"{BASE_URL}/api/psp/{TEST_PSP_ID}/pending-transactions",
            headers=auth_headers
        )
        assert response.status_code == 200
        transactions = response.json()
        
        if transactions:
            tx = transactions[0]
            
            # Verify holding fields
            assert "psp_holding_days" in tx, "Missing psp_holding_days"
            assert "psp_holding_release_date" in tx, "Missing psp_holding_release_date"
            assert "psp_chargeback_rate" in tx, "Missing psp_chargeback_rate"
            
            print(f"Transaction holding_days={tx.get('psp_holding_days')}")
            print(f"Transaction release_date={tx.get('psp_holding_release_date')}")
            print(f"Transaction chargeback_rate={tx.get('psp_chargeback_rate')}%")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
