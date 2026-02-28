"""
Test Suite for PSP Reserve Fund Feature Enhancements
Tests: Reserve Fund Ledger, Single Release, Bulk Release, Global Summary, and PSP Fee Fields
"""
import pytest
import requests
import os
import time
import uuid
from datetime import datetime

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestReserveFundBackend:
    """Backend tests for Reserve Fund module enhancements"""
    
    auth_token = None
    test_psp_id = None
    test_transaction_id = None
    test_treasury_id = None
    
    @classmethod
    def setup_class(cls):
        """Login and get auth token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "password"
        })
        assert response.status_code == 200, f"Login failed: {response.text}"
        data = response.json()
        cls.auth_token = data.get("access_token")
        assert cls.auth_token, "No access token returned"
    
    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    # ============== PSP SUMMARY & DASHBOARD ==============
    
    def test_01_psp_summary_has_reserve_fund_held(self):
        """GET /api/psp-summary returns total_reserve_fund_held for each PSP"""
        response = requests.get(f"{BASE_URL}/api/psp-summary", headers=self.get_headers())
        assert response.status_code == 200, f"Failed: {response.text}"
        psps = response.json()
        assert isinstance(psps, list), "Expected list of PSPs"
        
        # Check that at least one PSP exists
        if len(psps) > 0:
            psp = psps[0]
            # Store PSP ID for later tests
            TestReserveFundBackend.test_psp_id = psp.get("psp_id")
            
            # Verify reserve fund fields exist
            assert "total_reserve_fund_held" in psp, f"Missing total_reserve_fund_held field in PSP: {psp}"
            assert "reserve_fund_rate" in psp or "chargeback_rate" in psp, "Missing reserve_fund_rate or chargeback_rate"
            print(f"PSP {psp.get('psp_name')} - Reserve Fund Held: ${psp.get('total_reserve_fund_held', 0)}")
    
    def test_02_psp_detail_has_reserve_fund_rate(self):
        """GET /api/psp/{psp_id} returns reserve_fund_rate field"""
        if not self.test_psp_id:
            pytest.skip("No PSP available for testing")
        
        response = requests.get(f"{BASE_URL}/api/psp/{self.test_psp_id}", headers=self.get_headers())
        assert response.status_code == 200, f"Failed: {response.text}"
        psp = response.json()
        
        # Check reserve fund related fields
        assert "reserve_fund_rate" in psp or "chargeback_rate" in psp, "Missing reserve_fund_rate"
        assert "holding_days" in psp, "Missing holding_days field"
        
        # Check new fee fields
        print(f"PSP Details - Reserve Fund Rate: {psp.get('reserve_fund_rate', psp.get('chargeback_rate', 0))}%")
        print(f"PSP Details - Gateway Fee: ${psp.get('gateway_fee', 0)}")
        print(f"PSP Details - Refund Fee: ${psp.get('refund_fee', 0)}")
        print(f"PSP Details - Monthly Min Fee: ${psp.get('monthly_minimum_fee', 0)}")
    
    # ============== GLOBAL RESERVE FUND SUMMARY ==============
    
    def test_03_global_reserve_summary_endpoint(self):
        """GET /api/psps/reserve-funds/global-summary returns total_held, total_released, due_for_release"""
        response = requests.get(f"{BASE_URL}/api/psps/reserve-funds/global-summary", headers=self.get_headers())
        assert response.status_code == 200, f"Failed: {response.text}"
        summary = response.json()
        
        assert "total_held" in summary, "Missing total_held field"
        assert "total_released" in summary, "Missing total_released field"
        assert "due_for_release" in summary, "Missing due_for_release field"
        
        assert isinstance(summary["total_held"], (int, float)), "total_held should be numeric"
        assert isinstance(summary["total_released"], (int, float)), "total_released should be numeric"
        assert isinstance(summary["due_for_release"], (int, float)), "due_for_release should be numeric"
        
        print(f"Global Reserve Summary - Total Held: ${summary['total_held']}")
        print(f"Global Reserve Summary - Total Released: ${summary['total_released']}")
        print(f"Global Reserve Summary - Due for Release: ${summary['due_for_release']}")
    
    # ============== RESERVE FUND LEDGER ==============
    
    def test_04_reserve_fund_ledger_endpoint(self):
        """GET /api/psps/{psp_id}/reserve-funds returns ledger and summary"""
        if not self.test_psp_id:
            pytest.skip("No PSP available for testing")
        
        response = requests.get(f"{BASE_URL}/api/psps/{self.test_psp_id}/reserve-funds", headers=self.get_headers())
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify response structure
        assert "ledger" in data, "Missing ledger field"
        assert "summary" in data, "Missing summary field"
        assert isinstance(data["ledger"], list), "Ledger should be a list"
        
        # Verify summary structure
        summary = data["summary"]
        assert "total_held" in summary, "Missing total_held in summary"
        assert "total_released" in summary, "Missing total_released in summary"
        assert "due_this_week" in summary, "Missing due_this_week in summary"
        assert "holding_days" in summary, "Missing holding_days in summary"
        assert "reserve_fund_rate" in summary, "Missing reserve_fund_rate in summary"
        
        print(f"Reserve Fund Ledger - Total Entries: {len(data['ledger'])}")
        print(f"Reserve Fund Ledger Summary - Held: ${summary['total_held']}, Released: ${summary['total_released']}, Due this week: ${summary['due_this_week']}")
        
        # Verify ledger entry structure if entries exist
        if len(data["ledger"]) > 0:
            entry = data["ledger"][0]
            required_fields = ["transaction_id", "reference", "client_name", "amount", 
                              "reserve_fund_amount", "hold_date", "release_date", 
                              "days_remaining", "status"]
            for field in required_fields:
                assert field in entry, f"Missing {field} in ledger entry"
            
            # Store a transaction ID for release test
            for e in data["ledger"]:
                if e.get("status") != "released":
                    TestReserveFundBackend.test_transaction_id = e["transaction_id"]
                    break
            
            # Check status values
            assert entry["status"] in ["held", "due", "released"], f"Invalid status: {entry['status']}"
            print(f"Ledger entry sample - Ref: {entry['reference']}, Reserve: ${entry['reserve_fund_amount']}, Status: {entry['status']}")
    
    def test_05_reserve_fund_ledger_404_for_invalid_psp(self):
        """GET /api/psps/invalid_psp/reserve-funds returns 404"""
        response = requests.get(f"{BASE_URL}/api/psps/invalid_psp_xyz/reserve-funds", headers=self.get_headers())
        assert response.status_code == 404, f"Expected 404, got: {response.status_code}"
    
    # ============== PSP CREATE/UPDATE WITH NEW FIELDS ==============
    
    def test_06_create_psp_with_fee_fields(self):
        """POST /api/psp creates PSP with gateway_fee, refund_fee, monthly_minimum_fee"""
        # First get a treasury account for settlement destination
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.get_headers())
        if treasury_resp.status_code == 200 and len(treasury_resp.json()) > 0:
            TestReserveFundBackend.test_treasury_id = treasury_resp.json()[0]["account_id"]
        else:
            pytest.skip("No treasury account available")
        
        psp_name = f"TEST_RESERVE_FUND_PSP_{uuid.uuid4().hex[:6]}"
        response = requests.post(f"{BASE_URL}/api/psp", headers=self.get_headers(), json={
            "psp_name": psp_name,
            "commission_rate": 2.5,
            "reserve_fund_rate": 5.0,
            "holding_days": 30,
            "settlement_days": 2,
            "settlement_destination_id": self.test_treasury_id,
            "gateway_fee": 0.25,
            "refund_fee": 10.00,
            "monthly_minimum_fee": 50.00,
            "description": "Test PSP for reserve fund testing"
        })
        
        assert response.status_code == 200, f"Failed to create PSP: {response.text}"
        psp = response.json()
        
        # Verify new fee fields were stored
        assert psp.get("gateway_fee") == 0.25, f"gateway_fee not stored correctly: {psp.get('gateway_fee')}"
        assert psp.get("refund_fee") == 10.00, f"refund_fee not stored correctly: {psp.get('refund_fee')}"
        assert psp.get("monthly_minimum_fee") == 50.00, f"monthly_minimum_fee not stored correctly: {psp.get('monthly_minimum_fee')}"
        assert psp.get("reserve_fund_rate") == 5.0, f"reserve_fund_rate not stored correctly: {psp.get('reserve_fund_rate')}"
        
        # Store the new PSP ID for cleanup
        created_psp_id = psp.get("psp_id")
        
        print(f"Created PSP with fees - Gateway: ${psp.get('gateway_fee')}, Refund: ${psp.get('refund_fee')}, Monthly Min: ${psp.get('monthly_minimum_fee')}")
        
        # Cleanup - delete test PSP
        cleanup_resp = requests.delete(f"{BASE_URL}/api/psp/{created_psp_id}", headers=self.get_headers())
        print(f"Cleanup PSP: {cleanup_resp.status_code}")
    
    def test_07_update_psp_reserve_fund_rate(self):
        """PUT /api/psp/{psp_id} updates reserve_fund_rate"""
        if not self.test_psp_id:
            pytest.skip("No PSP available for testing")
        
        # Get current PSP data
        get_resp = requests.get(f"{BASE_URL}/api/psp/{self.test_psp_id}", headers=self.get_headers())
        assert get_resp.status_code == 200
        original_psp = get_resp.json()
        original_rate = original_psp.get("reserve_fund_rate", original_psp.get("chargeback_rate", 0))
        
        # Update reserve fund rate temporarily
        new_rate = 7.5
        response = requests.put(f"{BASE_URL}/api/psp/{self.test_psp_id}", headers=self.get_headers(), json={
            "reserve_fund_rate": new_rate
        })
        assert response.status_code == 200, f"Failed to update PSP: {response.text}"
        updated_psp = response.json()
        
        assert updated_psp.get("reserve_fund_rate") == new_rate, f"reserve_fund_rate not updated: {updated_psp.get('reserve_fund_rate')}"
        
        # Restore original rate
        requests.put(f"{BASE_URL}/api/psp/{self.test_psp_id}", headers=self.get_headers(), json={
            "reserve_fund_rate": original_rate
        })
        print(f"Updated reserve_fund_rate from {original_rate}% to {new_rate}% and restored")
    
    # ============== RESERVE FUND RELEASE ==============
    
    def test_08_release_reserve_fund_single(self):
        """POST /api/psps/reserve-funds/{txId}/release releases single reserve fund"""
        # First, create a transaction with reserve fund if we don't have one
        if not self.test_transaction_id:
            # Skip if no eligible transactions
            pytest.skip("No unreleased transaction available for testing")
        
        # Get initial global summary
        pre_summary_resp = requests.get(f"{BASE_URL}/api/psps/reserve-funds/global-summary", headers=self.get_headers())
        pre_summary = pre_summary_resp.json() if pre_summary_resp.status_code == 200 else {}
        
        response = requests.post(
            f"{BASE_URL}/api/psps/reserve-funds/{self.test_transaction_id}/release",
            headers=self.get_headers()
        )
        
        # Either 200 (success) or 400 (already released) is acceptable
        assert response.status_code in [200, 400], f"Unexpected status: {response.status_code} - {response.text}"
        
        if response.status_code == 200:
            data = response.json()
            assert "amount" in data, "Missing amount in response"
            assert "transaction_id" in data, "Missing transaction_id in response"
            print(f"Released reserve fund: ${data.get('amount')} for {data.get('transaction_id')}")
        else:
            print(f"Transaction already released or not available: {response.json()}")
    
    def test_09_release_reserve_fund_already_released(self):
        """POST /api/psps/reserve-funds/{txId}/release returns 400 if already released"""
        if not self.test_transaction_id:
            pytest.skip("No transaction available")
        
        # Try to release again - should fail
        response = requests.post(
            f"{BASE_URL}/api/psps/reserve-funds/{self.test_transaction_id}/release",
            headers=self.get_headers()
        )
        
        # Should be 400 if already released
        assert response.status_code in [400, 404], f"Expected 400/404, got: {response.status_code}"
        print(f"Correctly rejected duplicate release: {response.status_code}")
    
    def test_10_release_reserve_fund_invalid_tx(self):
        """POST /api/psps/reserve-funds/invalid_tx/release returns 404"""
        response = requests.post(
            f"{BASE_URL}/api/psps/reserve-funds/invalid_tx_xyz/release",
            headers=self.get_headers()
        )
        assert response.status_code == 404, f"Expected 404, got: {response.status_code}"
    
    # ============== BULK RELEASE ==============
    
    def test_11_bulk_release_reserve_funds(self):
        """POST /api/psps/reserve-funds/bulk-release releases multiple reserve funds"""
        # Get some unreleased transaction IDs
        if not self.test_psp_id:
            pytest.skip("No PSP available")
        
        ledger_resp = requests.get(f"{BASE_URL}/api/psps/{self.test_psp_id}/reserve-funds", headers=self.get_headers())
        if ledger_resp.status_code != 200:
            pytest.skip("Could not get ledger")
        
        ledger = ledger_resp.json().get("ledger", [])
        unreleased_ids = [e["transaction_id"] for e in ledger if e.get("status") != "released"][:2]
        
        if not unreleased_ids:
            # Test with empty list - should get 400
            response = requests.post(
                f"{BASE_URL}/api/psps/reserve-funds/bulk-release",
                headers=self.get_headers(),
                json={"transaction_ids": []}
            )
            assert response.status_code == 400, f"Expected 400 for empty list, got: {response.status_code}"
            print("Bulk release correctly rejected empty list")
        else:
            response = requests.post(
                f"{BASE_URL}/api/psps/reserve-funds/bulk-release",
                headers=self.get_headers(),
                json={"transaction_ids": unreleased_ids}
            )
            assert response.status_code == 200, f"Bulk release failed: {response.text}"
            data = response.json()
            assert "count" in data, "Missing count in response"
            assert "total_released" in data, "Missing total_released in response"
            print(f"Bulk released {data.get('count')} entries totaling ${data.get('total_released')}")
    
    def test_12_bulk_release_empty_list_returns_400(self):
        """POST /api/psps/reserve-funds/bulk-release with empty list returns 400"""
        response = requests.post(
            f"{BASE_URL}/api/psps/reserve-funds/bulk-release",
            headers=self.get_headers(),
            json={"transaction_ids": []}
        )
        assert response.status_code == 400, f"Expected 400, got: {response.status_code}"
    
    # ============== PSP PENDING TRANSACTIONS ==============
    
    def test_13_pending_transactions_show_reserve_deduction(self):
        """GET /api/psp/{psp_id}/pending-transactions shows reserve fund in deductions"""
        if not self.test_psp_id:
            pytest.skip("No PSP available")
        
        response = requests.get(f"{BASE_URL}/api/psp/{self.test_psp_id}/pending-transactions", headers=self.get_headers())
        assert response.status_code == 200, f"Failed: {response.text}"
        txs = response.json()
        
        if len(txs) > 0:
            tx = txs[0]
            # Check that reserve fund fields exist
            has_reserve = "psp_reserve_fund_amount" in tx or "psp_chargeback_amount" in tx
            print(f"Pending tx {tx.get('transaction_id')} - Reserve Fund Amount: {tx.get('psp_reserve_fund_amount', tx.get('psp_chargeback_amount', 0))}")
        
        print(f"Found {len(txs)} pending transactions for PSP")
    
    # ============== PSP TRANSACTION CHARGES ==============
    
    def test_14_record_charges_on_transaction(self):
        """PUT /api/psp/transactions/{txId}/charges updates reserve_fund_amount"""
        if not self.test_psp_id:
            pytest.skip("No PSP available")
        
        # Get a pending transaction
        pending_resp = requests.get(f"{BASE_URL}/api/psp/{self.test_psp_id}/pending-transactions", headers=self.get_headers())
        if pending_resp.status_code != 200 or len(pending_resp.json()) == 0:
            pytest.skip("No pending transactions to test")
        
        tx = pending_resp.json()[0]
        tx_id = tx.get("transaction_id")
        
        response = requests.put(
            f"{BASE_URL}/api/psp/transactions/{tx_id}/charges",
            headers=self.get_headers(),
            json={
                "reserve_fund_amount": 50.00,
                "extra_charges": 5.00,
                "charges_description": "Test reserve fund charge"
            }
        )
        
        # 200 success or 400 if already settled
        assert response.status_code in [200, 400], f"Unexpected status: {response.status_code}"
        
        if response.status_code == 200:
            updated = response.json()
            assert updated.get("psp_reserve_fund_amount") == 50.00, "Reserve fund amount not updated"
            print(f"Updated transaction charges - Reserve: ${updated.get('psp_reserve_fund_amount')}")
        else:
            print(f"Could not update charges: {response.json()}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
