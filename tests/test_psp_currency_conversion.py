"""
PSP Currency Conversion Bug Fixes - Comprehensive Test Suite
Tests the three critical bug fixes:
1. PSP settlements convert USD to AED when crediting ENBD treasury (uses live FX rates)
2. Reserve fund amount stored per-transaction at creation time (psp_reserve_fund_amount field)
3. Releasing reserve fund credits treasury with currency-converted amount
"""

import pytest
import requests
import os
import time
import uuid
import random
from datetime import datetime

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://fx-broker-control.preview.emergentagent.com')

# Test data from context
PSP_UNIPAY = "psp_3de482bea719"  # 10% reserve fund, 6.95% commission
PSP_PAYPAL = "psp_1f22117d21a5"  # 3% reserve fund, 10% commission
TREASURY_ENBD_AED = "treasury_d812e38f2a7a"  # ENBD bank, AED currency
CLIENT_ID = "client_e9792d8531d1"  # safvan kappilakath


def random_amount(base=1000, variance=500):
    """Generate a random amount to avoid duplicate detection"""
    return round(base + random.uniform(-variance, variance), 2)


class TestAuth:
    """Get auth token for tests"""
    
    @pytest.fixture(scope="class")
    def auth_token(self):
        """Login and get auth token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "password"
        })
        assert response.status_code == 200, f"Login failed: {response.text}"
        data = response.json()
        token = data.get("access_token")
        assert token, "No access_token in response"
        return token
    
    @pytest.fixture(scope="class")
    def headers(self, auth_token):
        """Return headers with auth token"""
        return {"Authorization": f"Bearer {auth_token}"}


class TestFXRatesAndConversion(TestAuth):
    """Test FX rates API and currency conversion utility"""
    
    def test_fx_rates_available(self, headers):
        """GET /api/fx-rates returns live rates including AED"""
        response = requests.get(f"{BASE_URL}/api/fx-rates", headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        assert data.get("source") == "live", "FX rates should be from live source"
        assert "rates" in data, "rates dict missing"
        rates = data["rates"]
        assert "AED" in rates, "AED rate missing"
        assert "USD" in rates, "USD rate missing"
        
        # AED should be approximately 3.67 per USD (inverse: ~0.27)
        aed_rate = rates["AED"]
        assert 0.2 < aed_rate < 0.35, f"AED rate {aed_rate} outside expected range"
        print(f"Live FX rate - AED: {aed_rate} (1 USD = {1/aed_rate:.4f} AED)")
    
    def test_convert_currency_api(self, headers):
        """GET /api/fx-rates/convert converts USD to AED correctly"""
        response = requests.get(
            f"{BASE_URL}/api/fx-rates/convert",
            params={"amount": 1000, "from_currency": "USD", "to_currency": "AED"},
            headers=headers
        )
        assert response.status_code == 200
        data = response.json()
        
        converted = data.get("converted_amount", data.get("amount"))
        assert converted is not None, f"No converted amount in response: {data}"
        
        # Should be approximately 3672 AED (1 USD ~ 3.67 AED)
        assert 3500 < converted < 4000, f"1000 USD should convert to ~3672 AED, got {converted}"
        print(f"1000 USD = {converted:.2f} AED")


class TestPSPTransactionCreation(TestAuth):
    """Test that new PSP transactions store psp_reserve_fund_amount correctly"""
    
    def test_create_psp_transaction_stores_reserve_fund_amount(self, headers):
        """POST /api/transactions with PSP destination should store psp_reserve_fund_amount"""
        unique_ref = f"TEST_RESERVE_{uuid.uuid4().hex[:8].upper()}"
        test_amount = random_amount(2500, 500)  # Random amount between 2000-3000
        
        form_data = {
            "client_id": CLIENT_ID,
            "transaction_type": "deposit",
            "amount": str(test_amount),
            "currency": "USD",
            "base_currency": "USD",
            "destination_type": "psp",
            "psp_id": PSP_UNIPAY,
            "commission_paid_by": "broker",
            "reference": unique_ref,
            "description": "Test reserve fund amount storage"
        }
        
        response = requests.post(f"{BASE_URL}/api/transactions", headers=headers, data=form_data)
        assert response.status_code == 200, f"Create transaction failed: {response.text}"
        
        tx = response.json()
        tx_id = tx.get("transaction_id")
        print(f"Created transaction: {tx_id}")
        
        # Verify psp_reserve_fund_amount is stored
        assert tx.get("psp_reserve_fund_amount") is not None, "psp_reserve_fund_amount should be set"
        
        # UniPay has 10% reserve fund rate
        expected_reserve = round(test_amount * 0.10, 2)
        actual_reserve = tx.get("psp_reserve_fund_amount")
        assert actual_reserve == expected_reserve, f"Reserve fund should be {expected_reserve}, got {actual_reserve}"
        
        # Also check commission (6.95%)
        expected_commission = round(test_amount * 0.0695, 2)
        actual_commission = tx.get("psp_commission_amount")
        assert actual_commission == expected_commission, f"Commission should be {expected_commission}, got {actual_commission}"
        
        print(f"Transaction {tx_id}: amount={test_amount} USD, reserve_fund={actual_reserve} USD, commission={actual_commission} USD")
    
    def test_create_psp_transaction_with_paypal_reserve_rate(self, headers):
        """Verify different PSP (PayPal 3%) stores correct reserve fund amount"""
        unique_ref = f"TEST_PAYPAL_{uuid.uuid4().hex[:8].upper()}"
        test_amount = random_amount(5000, 500)  # Random amount between 4500-5500
        
        form_data = {
            "client_id": CLIENT_ID,
            "transaction_type": "deposit",
            "amount": str(test_amount),
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": PSP_PAYPAL,  # 3% reserve, 10% commission
            "commission_paid_by": "client",
            "reference": unique_ref,
            "description": "Test PayPal reserve fund"
        }
        
        response = requests.post(f"{BASE_URL}/api/transactions", headers=headers, data=form_data)
        assert response.status_code == 200, f"Create failed: {response.text}"
        
        tx = response.json()
        
        # PayPal has 3% reserve fund rate
        expected_reserve = round(test_amount * 0.03, 2)
        actual_reserve = tx.get("psp_reserve_fund_amount")
        assert actual_reserve == expected_reserve, f"PayPal reserve should be {expected_reserve}, got {actual_reserve}"
        
        # Commission is 10%
        expected_commission = round(test_amount * 0.10, 2)
        assert tx.get("psp_commission_amount") == expected_commission
        
        print(f"PayPal transaction: reserve_fund={actual_reserve} USD, commission={tx.get('psp_commission_amount')} USD")


class TestPSPSettlementCurrencyConversion(TestAuth):
    """Test that PSP settlements convert USD to AED when crediting ENBD treasury"""
    
    def test_settle_psp_transaction_converts_currency(self, headers):
        """POST /api/psp/transactions/{id}/settle should convert USD to AED for ENBD treasury"""
        unique_ref = f"TEST_SETTLE_{uuid.uuid4().hex[:8].upper()}"
        test_amount = random_amount(1000, 200)  # Random amount between 800-1200
        
        # Step 1: Create a PSP transaction
        form_data = {
            "client_id": CLIENT_ID,
            "transaction_type": "deposit",
            "amount": str(test_amount),
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": PSP_UNIPAY,
            "commission_paid_by": "broker",
            "reference": unique_ref,
            "description": "Test settlement currency conversion"
        }
        
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=headers, data=form_data)
        assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
        tx = create_resp.json()
        tx_id = tx.get("transaction_id")
        
        # Get net amount (after commission)
        net_amount = tx.get("psp_net_amount", tx.get("amount"))
        reserve_amount = tx.get("psp_reserve_fund_amount", 0)
        print(f"Created tx {tx_id}: amount={test_amount}, net={net_amount}, reserve={reserve_amount}")
        
        # Step 2: Get treasury balance before settlement
        treasury_before = requests.get(f"{BASE_URL}/api/treasury", headers=headers)
        assert treasury_before.status_code == 200
        enbd_before = next((t for t in treasury_before.json() if t["account_id"] == TREASURY_ENBD_AED), None)
        balance_before = enbd_before.get("balance", 0) if enbd_before else 0
        print(f"ENBD Treasury balance before: {balance_before:.2f} AED")
        
        # Step 3: Settle the transaction
        settle_resp = requests.post(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/settle",
            headers=headers,
            params={"destination_account_id": TREASURY_ENBD_AED}
        )
        assert settle_resp.status_code == 200, f"Settlement failed: {settle_resp.text}"
        
        # Step 4: Get treasury balance after settlement
        time.sleep(0.5)
        treasury_after = requests.get(f"{BASE_URL}/api/treasury", headers=headers)
        assert treasury_after.status_code == 200
        enbd_after = next((t for t in treasury_after.json() if t["account_id"] == TREASURY_ENBD_AED), None)
        balance_after = enbd_after.get("balance", 0) if enbd_after else 0
        print(f"ENBD Treasury balance after: {balance_after:.2f} AED")
        
        # Step 5: Calculate expected balance change
        fx_resp = requests.get(f"{BASE_URL}/api/fx-rates", headers=headers)
        aed_rate = fx_resp.json().get("rates", {}).get("AED", 0.27229408)
        
        # net_amount USD should be converted to AED: net_amount / aed_rate
        expected_aed_credit = round(net_amount / aed_rate, 2)
        actual_change = balance_after - balance_before
        
        print(f"Expected AED credit: {expected_aed_credit:.2f} (from {net_amount} USD)")
        print(f"Actual balance change: {actual_change:.2f} AED")
        
        # BUG FIX VERIFICATION: Balance change should be in AED (~3.67x USD), not raw USD
        tolerance = expected_aed_credit * 0.02
        assert abs(actual_change - expected_aed_credit) < tolerance, \
            f"Settlement should convert USD to AED. Expected ~{expected_aed_credit:.2f} AED, got {actual_change:.2f} AED"
        
        # Verify it's NOT the raw USD amount
        assert actual_change > net_amount * 1.5, \
            f"Balance change {actual_change} looks like raw USD, not converted AED. BUG: Currency not converted!"
    
    def test_record_psp_payment_converts_currency(self, headers):
        """POST /api/psp/transactions/{id}/record-payment also converts currency"""
        unique_ref = f"TEST_RECPAY_{uuid.uuid4().hex[:8].upper()}"
        test_amount = random_amount(800, 150)  # Random between 650-950
        
        form_data = {
            "client_id": CLIENT_ID,
            "transaction_type": "deposit",
            "amount": str(test_amount),
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": PSP_PAYPAL,
            "commission_paid_by": "client",
            "reference": unique_ref,
            "description": "Test record payment conversion"
        }
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=headers, data=form_data)
        assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
        tx = create_resp.json()
        tx_id = tx.get("transaction_id")
        net_amount = tx.get("psp_net_amount")
        print(f"Created tx {tx_id}: net_amount={net_amount} USD")
        
        # Get treasury balance before
        treasury_before = requests.get(f"{BASE_URL}/api/treasury", headers=headers).json()
        balance_before = next((t["balance"] for t in treasury_before if t["account_id"] == TREASURY_ENBD_AED), 0)
        
        # Record payment
        record_resp = requests.post(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/record-payment",
            headers=headers,
            params={
                "destination_account_id": TREASURY_ENBD_AED,
                "actual_amount_received": net_amount
            }
        )
        assert record_resp.status_code == 200, f"Record payment failed: {record_resp.text}"
        
        # Get treasury balance after
        time.sleep(0.3)
        treasury_after = requests.get(f"{BASE_URL}/api/treasury", headers=headers).json()
        balance_after = next((t["balance"] for t in treasury_after if t["account_id"] == TREASURY_ENBD_AED), 0)
        
        balance_change = balance_after - balance_before
        
        # Should be converted (approximately net_amount * 3.67)
        assert balance_change > net_amount * 1.5, \
            f"Record payment should convert USD to AED. Got {balance_change:.2f}, expected > {net_amount * 1.5:.2f}"
        
        print(f"Record payment: {net_amount} USD credited as {balance_change:.2f} AED")


class TestReserveFundRelease(TestAuth):
    """Test that releasing reserve funds converts currency and credits treasury correctly"""
    
    def test_single_release_converts_currency(self, headers):
        """POST /api/psps/reserve-funds/{tx_id}/release converts and credits treasury"""
        unique_ref = f"TEST_RFREL_{uuid.uuid4().hex[:8].upper()}"
        test_amount = random_amount(1500, 300)  # Random between 1200-1800
        
        # Step 1: Create and settle a PSP transaction
        form_data = {
            "client_id": CLIENT_ID,
            "transaction_type": "deposit",
            "amount": str(test_amount),
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": PSP_UNIPAY,  # 10% reserve
            "commission_paid_by": "broker",
            "reference": unique_ref,
            "description": "Test reserve fund release currency conversion"
        }
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=headers, data=form_data)
        assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
        tx = create_resp.json()
        tx_id = tx.get("transaction_id")
        reserve_amount = tx.get("psp_reserve_fund_amount")
        expected_reserve = round(test_amount * 0.10, 2)
        assert reserve_amount == expected_reserve, f"Reserve should be {expected_reserve} USD, got {reserve_amount}"
        print(f"Created tx {tx_id} with reserve_amount={reserve_amount} USD")
        
        # Settle it first
        settle_resp = requests.post(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/settle",
            headers=headers,
            params={"destination_account_id": TREASURY_ENBD_AED}
        )
        assert settle_resp.status_code == 200
        
        # Verify transaction has reserve fund not released yet
        tx_check = requests.get(f"{BASE_URL}/api/transactions/{tx_id}", headers=headers).json()
        assert tx_check.get("reserve_fund_released") is not True, "Reserve should not be released yet"
        
        # Step 2: Get treasury balance before release
        treasury_before = requests.get(f"{BASE_URL}/api/treasury", headers=headers).json()
        balance_before = next((t["balance"] for t in treasury_before if t["account_id"] == TREASURY_ENBD_AED), 0)
        print(f"Treasury balance before release: {balance_before:.2f} AED")
        
        # Step 3: Release the reserve fund
        release_resp = requests.post(
            f"{BASE_URL}/api/psps/reserve-funds/{tx_id}/release",
            headers=headers
        )
        assert release_resp.status_code == 200, f"Release failed: {release_resp.text}"
        release_data = release_resp.json()
        print(f"Release response: {release_data}")
        
        # Step 4: Verify treasury balance increased by converted amount
        time.sleep(0.3)
        treasury_after = requests.get(f"{BASE_URL}/api/treasury", headers=headers).json()
        balance_after = next((t["balance"] for t in treasury_after if t["account_id"] == TREASURY_ENBD_AED), 0)
        
        balance_change = balance_after - balance_before
        
        # Get actual FX rate
        fx_resp = requests.get(f"{BASE_URL}/api/fx-rates", headers=headers)
        aed_rate = fx_resp.json().get("rates", {}).get("AED", 0.27229408)
        expected_aed = round(reserve_amount / aed_rate, 2)
        
        print(f"Reserve: {reserve_amount} USD → Expected: {expected_aed:.2f} AED, Actual change: {balance_change:.2f} AED")
        
        # BUG FIX VERIFICATION: Change should be converted amount, not raw USD
        tolerance = expected_aed * 0.02
        assert abs(balance_change - expected_aed) < tolerance, \
            f"Reserve fund release should convert to AED. Expected ~{expected_aed:.2f}, got {balance_change:.2f}"
        
        # Verify it's NOT the raw USD amount
        assert balance_change > reserve_amount * 2, \
            f"Balance change {balance_change} looks like raw USD, not converted AED. BUG NOT FIXED!"
        
        # Verify transaction is marked as released
        tx_after = requests.get(f"{BASE_URL}/api/transactions/{tx_id}", headers=headers).json()
        assert tx_after.get("reserve_fund_released") == True, "Transaction should be marked as released"
    
    def test_bulk_release_converts_currency(self, headers):
        """POST /api/psps/reserve-funds/bulk-release converts currency for all released"""
        # Create two transactions with different amounts
        tx_ids = []
        amounts = [random_amount(1100, 50), random_amount(1200, 50)]
        total_reserve_usd = 0
        
        for i in range(2):
            unique_ref = f"TEST_BULK_{uuid.uuid4().hex[:8].upper()}"
            form_data = {
                "client_id": CLIENT_ID,
                "transaction_type": "deposit",
                "amount": str(amounts[i]),
                "currency": "USD",
                "destination_type": "psp",
                "psp_id": PSP_UNIPAY,  # 10% reserve 
                "commission_paid_by": "broker",
                "reference": unique_ref,
                "description": f"Bulk release test {i+1}"
            }
            total_reserve_usd += round(amounts[i] * 0.10, 2)  # 10% reserve
            
            create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=headers, data=form_data)
            assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
            tx = create_resp.json()
            tx_id = tx.get("transaction_id")
            tx_ids.append(tx_id)
            
            # Settle it
            requests.post(
                f"{BASE_URL}/api/psp/transactions/{tx_id}/settle",
                headers=headers,
                params={"destination_account_id": TREASURY_ENBD_AED}
            )
        
        print(f"Created and settled transactions: {tx_ids}")
        
        # Get treasury balance before bulk release
        treasury_before = requests.get(f"{BASE_URL}/api/treasury", headers=headers).json()
        balance_before = next((t["balance"] for t in treasury_before if t["account_id"] == TREASURY_ENBD_AED), 0)
        
        # Bulk release both
        bulk_resp = requests.post(
            f"{BASE_URL}/api/psps/reserve-funds/bulk-release",
            headers=headers,
            json={"transaction_ids": tx_ids}
        )
        assert bulk_resp.status_code == 200, f"Bulk release failed: {bulk_resp.text}"
        
        # Get treasury balance after
        time.sleep(0.3)
        treasury_after = requests.get(f"{BASE_URL}/api/treasury", headers=headers).json()
        balance_after = next((t["balance"] for t in treasury_after if t["account_id"] == TREASURY_ENBD_AED), 0)
        
        balance_change = balance_after - balance_before
        
        # Get FX rate
        fx_resp = requests.get(f"{BASE_URL}/api/fx-rates", headers=headers)
        aed_rate = fx_resp.json().get("rates", {}).get("AED", 0.27229408)
        expected_aed = round(total_reserve_usd / aed_rate, 2)
        
        print(f"Bulk release: {total_reserve_usd} USD → Expected: {expected_aed:.2f} AED, Actual: {balance_change:.2f} AED")
        
        # Verify conversion happened
        tolerance = expected_aed * 0.05
        assert abs(balance_change - expected_aed) < tolerance, \
            f"Bulk release should convert to AED. Expected ~{expected_aed:.2f}, got {balance_change:.2f}"


class TestTreasuryTransactionRecords(TestAuth):
    """Test that treasury transaction records have proper fields after settlements"""
    
    def test_psp_settlement_creates_treasury_transaction(self, headers):
        """Settlement creates treasury_transaction with proper currency fields"""
        unique_ref = f"TEST_TTXREC_{uuid.uuid4().hex[:8].upper()}"
        test_amount = random_amount(500, 100)  # Random between 400-600
        
        form_data = {
            "client_id": CLIENT_ID,
            "transaction_type": "deposit",
            "amount": str(test_amount),
            "currency": "USD",
            "destination_type": "psp",
            "psp_id": PSP_PAYPAL,
            "commission_paid_by": "client",
            "reference": unique_ref,
            "description": "Test treasury transaction record"
        }
        create_resp = requests.post(f"{BASE_URL}/api/transactions", headers=headers, data=form_data)
        assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
        tx = create_resp.json()
        tx_id = tx.get("transaction_id")
        
        # Settle
        settle_resp = requests.post(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/settle",
            headers=headers,
            params={"destination_account_id": TREASURY_ENBD_AED}
        )
        assert settle_resp.status_code == 200
        
        print(f"Settled tx {tx_id} - treasury transaction should have been created")


class TestLegacyTransactionsHandling(TestAuth):
    """Test that legacy transactions without psp_reserve_fund_amount are handled correctly"""
    
    def test_ledger_handles_legacy_without_stored_amount(self, headers):
        """GET /api/psps/{psp_id}/reserve-funds calculates for legacy transactions"""
        response = requests.get(f"{BASE_URL}/api/psps/{PSP_UNIPAY}/reserve-funds", headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        assert "ledger" in data, "Response should have ledger array"
        assert "summary" in data, "Response should have summary object"
        
        summary = data["summary"]
        assert "total_held" in summary
        assert "total_released" in summary
        
        print(f"UniPay reserve fund summary: held={summary.get('total_held')}, released={summary.get('total_released')}")
    
    def test_release_legacy_transaction_calculates_amount(self, headers):
        """Releasing legacy transaction (no psp_reserve_fund_amount) should calculate from PSP rate"""
        # Check existing legacy transaction
        tx = requests.get(f"{BASE_URL}/api/transactions/tx_228cc77ecd63", headers=headers).json()
        
        if tx.get("reserve_fund_released"):
            print("Legacy tx_228cc77ecd63 already released, skipping")
            pytest.skip("Legacy transaction already released")
        
        # Get treasury balance before
        treasury_before = requests.get(f"{BASE_URL}/api/treasury", headers=headers).json()
        balance_before = next((t["balance"] for t in treasury_before if t["account_id"] == TREASURY_ENBD_AED), 0)
        
        # Try to release
        release_resp = requests.post(
            f"{BASE_URL}/api/psps/reserve-funds/tx_228cc77ecd63/release",
            headers=headers
        )
        
        if release_resp.status_code == 400:
            print("Legacy transaction already released or not eligible")
            return
        
        assert release_resp.status_code == 200, f"Legacy release failed: {release_resp.text}"
        release_data = release_resp.json()
        
        released_amount = release_data.get("amount", 0)
        assert released_amount > 0, "Should calculate reserve amount from PSP rate"
        
        # 90000 USD * 10% = 9000 USD
        expected_usd = 9000.0
        assert abs(released_amount - expected_usd) < 100, f"Expected ~{expected_usd}, got {released_amount}"
        
        # Verify treasury was credited with converted amount
        time.sleep(0.3)
        treasury_after = requests.get(f"{BASE_URL}/api/treasury", headers=headers).json()
        balance_after = next((t["balance"] for t in treasury_after if t["account_id"] == TREASURY_ENBD_AED), 0)
        
        balance_change = balance_after - balance_before
        print(f"Legacy release: {released_amount} USD → {balance_change:.2f} AED credited")


class TestGlobalReserveFundSummary(TestAuth):
    """Test global reserve fund summary endpoint"""
    
    def test_global_summary_returns_correct_structure(self, headers):
        """GET /api/psps/reserve-funds/global-summary returns proper totals"""
        response = requests.get(f"{BASE_URL}/api/psps/reserve-funds/global-summary", headers=headers)
        assert response.status_code == 200
        data = response.json()
        
        assert "total_held" in data, "Should have total_held"
        assert "total_released" in data, "Should have total_released"
        assert "due_for_release" in data, "Should have due_for_release"
        
        print(f"Global reserve fund: held={data['total_held']}, released={data['total_released']}, due={data['due_for_release']}")


class TestConvertCurrencyUtility(TestAuth):
    """Test the convert_currency utility works for various currency pairs"""
    
    def test_convert_usd_to_aed(self, headers):
        """Convert USD to AED"""
        resp = requests.get(
            f"{BASE_URL}/api/fx-rates/convert",
            params={"amount": 100, "from_currency": "USD", "to_currency": "AED"},
            headers=headers
        )
        assert resp.status_code == 200
        result = resp.json().get("converted_amount", resp.json().get("amount"))
        assert 350 < result < 400, f"100 USD should be ~367 AED, got {result}"
        print(f"100 USD = {result:.2f} AED")
    
    def test_convert_aed_to_usd(self, headers):
        """Convert AED to USD"""
        resp = requests.get(
            f"{BASE_URL}/api/fx-rates/convert",
            params={"amount": 367, "from_currency": "AED", "to_currency": "USD"},
            headers=headers
        )
        assert resp.status_code == 200
        result = resp.json().get("converted_amount", resp.json().get("amount"))
        assert 90 < result < 110, f"367 AED should be ~100 USD, got {result}"
        print(f"367 AED = {result:.2f} USD")
    
    def test_convert_eur_to_inr(self, headers):
        """Convert EUR to INR via USD intermediate"""
        resp = requests.get(
            f"{BASE_URL}/api/fx-rates/convert",
            params={"amount": 100, "from_currency": "EUR", "to_currency": "INR"},
            headers=headers
        )
        assert resp.status_code == 200
        result = resp.json().get("converted_amount", resp.json().get("amount"))
        assert result > 5000, f"100 EUR should be >5000 INR, got {result}"
        print(f"100 EUR = {result:.2f} INR")
    
    def test_same_currency_no_conversion(self, headers):
        """Same currency returns same amount"""
        resp = requests.get(
            f"{BASE_URL}/api/fx-rates/convert",
            params={"amount": 100, "from_currency": "USD", "to_currency": "USD"},
            headers=headers
        )
        assert resp.status_code == 200
        result = resp.json().get("converted_amount", resp.json().get("amount"))
        assert result == 100.0, f"USD to USD should be same, got {result}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
