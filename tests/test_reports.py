"""
Reports Module API Tests
Tests for comprehensive reports endpoints: Transactions, Vendor, Commissions, Clients, Treasury, PSP, Financial
"""

import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials from context
ADMIN_EMAIL = "admin@fxbroker.com"
ADMIN_PASSWORD = "password"


@pytest.fixture(scope="module")
def auth_token():
    """Get admin authentication token"""
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    if response.status_code == 200:
        return response.json().get("access_token")
    pytest.skip("Authentication failed - skipping tests")


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Auth headers for API requests"""
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }


class TestAuthAndHealth:
    """Basic health and auth tests"""
    
    def test_health_endpoint(self):
        """Test API is reachable"""
        response = requests.get(f"{BASE_URL}/api")
        assert response.status_code in [200, 404], f"API not reachable: {response.status_code}"
    
    def test_admin_login(self):
        """Test admin can login"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        assert response.status_code == 200, f"Login failed: {response.text}"
        data = response.json()
        assert "access_token" in data
        assert data["user"]["email"] == ADMIN_EMAIL


class TestTransactionsDetailedReport:
    """Tests for /api/reports/transactions-detailed endpoint"""
    
    def test_get_transactions_detailed_report(self, auth_headers):
        """Test fetching detailed transactions report"""
        response = requests.get(
            f"{BASE_URL}/api/reports/transactions-detailed",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify structure
        assert "summary" in data, "Missing summary in response"
        assert "deposits_by_currency" in data, "Missing deposits_by_currency"
        assert "withdrawals_by_currency" in data, "Missing withdrawals_by_currency"
        
        # Verify summary fields
        summary = data["summary"]
        assert "total_deposits_usd" in summary
        assert "total_withdrawals_usd" in summary
        assert "net_flow_usd" in summary
        assert "deposit_count" in summary
        assert "withdrawal_count" in summary
        assert "total_count" in summary
        
        print(f"✓ Transactions Report: {summary['total_count']} transactions, Net flow: ${summary['net_flow_usd']}")
    
    def test_transactions_report_with_date_filter(self, auth_headers):
        """Test transactions report with date filters"""
        response = requests.get(
            f"{BASE_URL}/api/reports/transactions-detailed?start_date=2024-01-01&end_date=2030-12-31",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Date filter failed: {response.text}"
        data = response.json()
        assert "summary" in data
        print(f"✓ Date filter works: {data['summary']['total_count']} transactions in range")
    
    def test_deposits_by_currency_has_usd_equivalent(self, auth_headers):
        """Verify deposits breakdown has USD equivalent (base currency feature)"""
        response = requests.get(
            f"{BASE_URL}/api/reports/transactions-detailed",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        for deposit in data.get("deposits_by_currency", []):
            assert "currency" in deposit, "Missing currency field"
            assert "amount" in deposit, "Missing amount (base) field"
            assert "usd_equivalent" in deposit, "Missing usd_equivalent field"
            assert "count" in deposit, "Missing count field"
            print(f"✓ Deposit: {deposit['currency']} - {deposit['amount']} (${deposit['usd_equivalent']} USD)")


class TestVendorSummaryReport:
    """Tests for /api/reports/vendor-summary endpoint"""
    
    def test_get_vendor_summary_report(self, auth_headers):
        """Test fetching vendor summary report"""
        response = requests.get(
            f"{BASE_URL}/api/reports/vendor-summary",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify structure
        assert "vendors" in data, "Missing vendors in response"
        assert "grand_totals" in data, "Missing grand_totals"
        
        # Verify grand totals
        totals = data["grand_totals"]
        assert "total_deposits_usd" in totals
        assert "total_withdrawals_usd" in totals
        assert "total_commission_usd" in totals
        assert "total_net_settlement_usd" in totals
        assert "total_vendors" in totals
        
        print(f"✓ Vendor Report: {totals['total_vendors']} vendors, Net: ${totals['total_net_settlement_usd']}")
    
    def test_vendor_report_has_commission_deduction(self, auth_headers):
        """Verify vendor report shows commission deducted from settlement"""
        response = requests.get(
            f"{BASE_URL}/api/reports/vendor-summary",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        for vendor in data.get("vendors", []):
            assert "vendor_name" in vendor
            assert "totals" in vendor
            assert "currencies" in vendor
            
            totals = vendor["totals"]
            # Net = Deposits - Withdrawals - Commission
            expected_net = totals["deposits_usd"] - totals["withdrawals_usd"] - totals["commission_usd"]
            assert abs(totals["net_settlement_usd"] - expected_net) < 0.01, f"Net settlement calculation error for {vendor['vendor_name']}"
            
            print(f"✓ Vendor {vendor['vendor_name']}: D=${totals['deposits_usd']}, W=${totals['withdrawals_usd']}, C=${totals['commission_usd']}, Net=${totals['net_settlement_usd']}")


class TestVendorCommissionsReport:
    """Tests for /api/reports/vendor-commissions endpoint"""
    
    def test_get_vendor_commissions_report(self, auth_headers):
        """Test fetching vendor commissions report"""
        response = requests.get(
            f"{BASE_URL}/api/reports/vendor-commissions",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify structure
        assert "vendors" in data, "Missing vendors"
        assert "total_commission_usd" in data, "Missing total_commission_usd"
        
        print(f"✓ Commissions Report: Total commission = ${data['total_commission_usd']}")
    
    def test_commission_breakdown_by_vendor(self, auth_headers):
        """Verify commission breakdown per vendor"""
        response = requests.get(
            f"{BASE_URL}/api/reports/vendor-commissions",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        for vendor in data.get("vendors", []):
            assert "vendor_name" in vendor
            assert "total_commission_usd" in vendor
            assert "deposit_commissions" in vendor
            assert "withdrawal_commissions" in vendor
            assert "transaction_count" in vendor
            assert "commission_by_currency" in vendor
            
            print(f"✓ {vendor['vendor_name']}: ${vendor['total_commission_usd']} (D: ${vendor['deposit_commissions']}, W: ${vendor['withdrawal_commissions']})")


class TestClientBalancesReport:
    """Tests for /api/reports/client-balances endpoint"""
    
    def test_get_client_balances_report(self, auth_headers):
        """Test fetching client balances report"""
        response = requests.get(
            f"{BASE_URL}/api/reports/client-balances",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify structure
        assert "clients" in data, "Missing clients"
        assert "summary" in data, "Missing summary"
        
        summary = data["summary"]
        assert "total_clients" in summary
        assert "total_deposits_usd" in summary
        assert "total_withdrawals_usd" in summary
        assert "total_net_balance" in summary
        assert "active_clients" in summary
        
        print(f"✓ Client Report: {summary['total_clients']} clients, Active: {summary['active_clients']}, Net: ${summary['total_net_balance']}")
    
    def test_client_balances_detail(self, auth_headers):
        """Verify client details in balance report"""
        response = requests.get(
            f"{BASE_URL}/api/reports/client-balances",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        for client in data.get("clients", [])[:5]:  # Check first 5
            assert "client_id" in client
            assert "name" in client
            assert "total_deposits_usd" in client
            assert "total_withdrawals_usd" in client
            assert "net_balance" in client
            assert "transaction_count" in client
            
            # Verify net balance calculation
            expected_net = client["total_deposits_usd"] - client["total_withdrawals_usd"]
            assert abs(client["net_balance"] - expected_net) < 0.01, f"Net balance calculation error for {client['name']}"
            
            print(f"✓ Client {client['name']}: D=${client['total_deposits_usd']}, W=${client['total_withdrawals_usd']}, Net=${client['net_balance']}")


class TestTreasurySummaryReport:
    """Tests for /api/reports/treasury-summary endpoint"""
    
    def test_get_treasury_summary_report(self, auth_headers):
        """Test fetching treasury summary report"""
        response = requests.get(
            f"{BASE_URL}/api/reports/treasury-summary",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify structure
        assert "accounts" in data, "Missing accounts"
        assert "total_balance_usd" in data, "Missing total_balance_usd"
        assert "balance_by_currency" in data, "Missing balance_by_currency"
        
        print(f"✓ Treasury Report: {len(data['accounts'])} accounts, Total: ${data['total_balance_usd']}")
    
    def test_treasury_balance_by_currency(self, auth_headers):
        """Verify treasury balances grouped by currency"""
        response = requests.get(
            f"{BASE_URL}/api/reports/treasury-summary",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        for curr in data.get("balance_by_currency", []):
            assert "currency" in curr
            assert "total" in curr
            assert "account_count" in curr
            print(f"✓ Treasury {curr['currency']}: {curr['total']} ({curr['account_count']} accounts)")
    
    def test_treasury_accounts_have_usd_equivalent(self, auth_headers):
        """Verify treasury accounts show USD equivalent"""
        response = requests.get(
            f"{BASE_URL}/api/reports/treasury-summary",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        for acc in data.get("accounts", []):
            assert "balance" in acc, "Missing balance"
            assert "balance_usd" in acc, "Missing balance_usd"
            assert "currency" in acc, "Missing currency"
            print(f"✓ Account {acc['account_name']}: {acc['currency']} {acc['balance']} (${acc['balance_usd']} USD)")


class TestPSPSummaryReport:
    """Tests for /api/reports/psp-summary endpoint"""
    
    def test_get_psp_summary_report(self, auth_headers):
        """Test fetching PSP summary report"""
        response = requests.get(
            f"{BASE_URL}/api/reports/psp-summary",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify structure
        assert "psps" in data, "Missing psps"
        assert "grand_totals" in data, "Missing grand_totals"
        
        totals = data["grand_totals"]
        assert "total_volume" in totals
        assert "total_commission" in totals
        assert "total_net" in totals
        assert "total_transactions" in totals
        
        print(f"✓ PSP Report: Volume=${totals['total_volume']}, Commission=${totals['total_commission']}")
    
    def test_psp_details_structure(self, auth_headers):
        """Verify PSP details in report"""
        response = requests.get(
            f"{BASE_URL}/api/reports/psp-summary",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        for psp in data.get("psps", []):
            assert "psp_name" in psp
            assert "commission_rate" in psp
            assert "total_volume" in psp
            assert "total_commission" in psp
            assert "total_net" in psp
            assert "settled_count" in psp
            assert "pending_count" in psp
            print(f"✓ PSP {psp['psp_name']}: Vol=${psp['total_volume']}, Settled={psp['settled_count']}, Pending={psp['pending_count']}")


class TestFinancialSummaryReport:
    """Tests for /api/reports/financial-summary endpoint"""
    
    def test_get_financial_summary_report(self, auth_headers):
        """Test fetching financial summary report (P&L)"""
        response = requests.get(
            f"{BASE_URL}/api/reports/financial-summary",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Verify structure
        assert "income" in data, "Missing income"
        assert "expenses" in data, "Missing expenses"
        assert "net_profit_loss" in data, "Missing net_profit_loss"
        assert "loans" in data, "Missing loans"
        assert "treasury" in data, "Missing treasury"
        
        print(f"✓ Financial Report: Income=${data['income']['total']}, Expenses=${data['expenses']['total']}, P&L=${data['net_profit_loss']}")
    
    def test_financial_pnl_calculation(self, auth_headers):
        """Verify P&L is correctly calculated"""
        response = requests.get(
            f"{BASE_URL}/api/reports/financial-summary",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        expected_pnl = data["income"]["total"] - data["expenses"]["total"]
        assert abs(data["net_profit_loss"] - expected_pnl) < 0.01, "P&L calculation error"
        print(f"✓ P&L verified: {data['income']['total']} - {data['expenses']['total']} = {data['net_profit_loss']}")
    
    def test_loan_summary_structure(self, auth_headers):
        """Verify loan summary fields"""
        response = requests.get(
            f"{BASE_URL}/api/reports/financial-summary",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        loans = data["loans"]
        assert "total_disbursed" in loans
        assert "total_outstanding" in loans
        assert "total_repaid" in loans
        assert "active_loans" in loans
        
        print(f"✓ Loans: Disbursed=${loans['total_disbursed']}, Outstanding=${loans['total_outstanding']}, Repaid=${loans['total_repaid']}, Active={loans['active_loans']}")


class TestTransactionsSummaryChart:
    """Tests for /api/reports/transactions-summary chart data endpoint"""
    
    def test_get_transactions_summary_chart(self, auth_headers):
        """Test fetching transactions summary for charts"""
        response = requests.get(
            f"{BASE_URL}/api/reports/transactions-summary?days=30",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        
        # Should be a list of daily summaries
        assert isinstance(data, list), "Expected list response"
        print(f"✓ Chart data: {len(data)} days of data")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
