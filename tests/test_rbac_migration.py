"""
Test suite for RBAC Migration - Full Endpoint Coverage
Tests migration from legacy decorators to require_permission(Module, Action) system

Features Tested:
1. Admin access to ALL major endpoints (200)
2. Vendor (Exchanger) gets 403 on admin-only endpoints
3. Vendor gets 200 on allowed endpoints (dashboard, transactions view, income_expenses view)
4. Unauthenticated requests get 401 on all protected endpoints
5. POST /api/transactions now requires authentication (was NO AUTH before)
6. Dashboard API requires permission (dashboard:view)
"""

import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
ADMIN_EMAIL = "admin@fxbroker.com"
ADMIN_PASSWORD = "admin123"
VENDOR_EMAIL = "kenway@fxbroker.com"
VENDOR_PASSWORD = "password"


class TestAdminFullAccess:
    """Test that Admin user gets 200 on all major endpoints"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # Login as admin once
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert login_resp.status_code == 200, f"Admin login failed: {login_resp.text}"
        self.token = login_resp.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_admin_dashboard(self):
        """Admin should access dashboard stats"""
        response = self.session.get(f"{BASE_URL}/api/reports/dashboard", headers=self.headers)
        assert response.status_code == 200, f"Dashboard failed: {response.text}"
        print("✓ Admin: GET /api/reports/dashboard - 200")

    def test_admin_clients(self):
        """Admin should access clients list"""
        response = self.session.get(f"{BASE_URL}/api/clients", headers=self.headers)
        assert response.status_code == 200, f"Clients failed: {response.text}"
        print("✓ Admin: GET /api/clients - 200")

    def test_admin_transactions(self):
        """Admin should access transactions list"""
        response = self.session.get(f"{BASE_URL}/api/transactions", headers=self.headers)
        assert response.status_code == 200, f"Transactions failed: {response.text}"
        print("✓ Admin: GET /api/transactions - 200")

    def test_admin_treasury(self):
        """Admin should access treasury accounts"""
        response = self.session.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        assert response.status_code == 200, f"Treasury failed: {response.text}"
        print("✓ Admin: GET /api/treasury - 200")

    def test_admin_lp_accounts(self):
        """Admin should access LP accounts"""
        response = self.session.get(f"{BASE_URL}/api/lp", headers=self.headers)
        assert response.status_code == 200, f"LP accounts failed: {response.text}"
        print("✓ Admin: GET /api/lp - 200")

    def test_admin_psp(self):
        """Admin should access PSP list"""
        response = self.session.get(f"{BASE_URL}/api/psp", headers=self.headers)
        assert response.status_code == 200, f"PSP failed: {response.text}"
        print("✓ Admin: GET /api/psp - 200")

    def test_admin_income_expenses(self):
        """Admin should access income/expenses list"""
        response = self.session.get(f"{BASE_URL}/api/income-expenses", headers=self.headers)
        assert response.status_code == 200, f"Income-Expenses failed: {response.text}"
        print("✓ Admin: GET /api/income-expenses - 200")

    def test_admin_loans(self):
        """Admin should access loans list"""
        response = self.session.get(f"{BASE_URL}/api/loans", headers=self.headers)
        assert response.status_code == 200, f"Loans failed: {response.text}"
        print("✓ Admin: GET /api/loans - 200")

    def test_admin_debts(self):
        """Admin should access debts (O/S accounts)"""
        response = self.session.get(f"{BASE_URL}/api/debts", headers=self.headers)
        assert response.status_code == 200, f"Debts failed: {response.text}"
        print("✓ Admin: GET /api/debts - 200")

    def test_admin_reconciliation(self):
        """Admin should access reconciliation summary"""
        response = self.session.get(f"{BASE_URL}/api/reconciliation/summary", headers=self.headers)
        assert response.status_code == 200, f"Reconciliation failed: {response.text}"
        print("✓ Admin: GET /api/reconciliation/summary - 200")

    def test_admin_audit(self):
        """Admin should access audit latest"""
        response = self.session.get(f"{BASE_URL}/api/audit/latest", headers=self.headers)
        # 200 if audit exists, 404 if no audit run yet
        assert response.status_code in [200, 404], f"Audit failed: {response.text}"
        print(f"✓ Admin: GET /api/audit/latest - {response.status_code}")

    def test_admin_logs(self):
        """Admin should access system logs"""
        response = self.session.get(f"{BASE_URL}/api/logs", headers=self.headers)
        assert response.status_code == 200, f"Logs failed: {response.text}"
        print("✓ Admin: GET /api/logs - 200")

    def test_admin_roles(self):
        """Admin should access roles list"""
        response = self.session.get(f"{BASE_URL}/api/roles", headers=self.headers)
        assert response.status_code == 200, f"Roles failed: {response.text}"
        print("✓ Admin: GET /api/roles - 200")

    def test_admin_email_settings(self):
        """Admin should access email settings"""
        response = self.session.get(f"{BASE_URL}/api/settings/email", headers=self.headers)
        assert response.status_code == 200, f"Settings failed: {response.text}"
        print("✓ Admin: GET /api/settings/email - 200")

    def test_admin_users(self):
        """Admin should access users list"""
        response = self.session.get(f"{BASE_URL}/api/users", headers=self.headers)
        assert response.status_code == 200, f"Users failed: {response.text}"
        print("✓ Admin: GET /api/users - 200")

    def test_admin_reports_transactions_summary(self):
        """Admin should access transactions summary report"""
        response = self.session.get(f"{BASE_URL}/api/reports/transactions-summary", headers=self.headers)
        assert response.status_code == 200, f"Reports failed: {response.text}"
        print("✓ Admin: GET /api/reports/transactions-summary - 200")

    def test_admin_vendors(self):
        """Admin should access vendors/exchangers list"""
        response = self.session.get(f"{BASE_URL}/api/vendors", headers=self.headers)
        assert response.status_code == 200, f"Vendors failed: {response.text}"
        print("✓ Admin: GET /api/vendors - 200")


class TestVendorRestricted:
    """Test that Vendor (Exchanger) gets 403 on admin-only endpoints"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # Login as vendor
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": VENDOR_EMAIL,
            "password": VENDOR_PASSWORD
        })
        assert login_resp.status_code == 200, f"Vendor login failed: {login_resp.text}"
        self.token = login_resp.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_vendor_blocked_users(self):
        """Vendor should NOT access users list (403)"""
        response = self.session.get(f"{BASE_URL}/api/users", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/users - 403")

    def test_vendor_blocked_logs(self):
        """Vendor should NOT access system logs (403)"""
        response = self.session.get(f"{BASE_URL}/api/logs", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/logs - 403")

    def test_vendor_blocked_email_settings(self):
        """Vendor should NOT access email settings (403)"""
        response = self.session.get(f"{BASE_URL}/api/settings/email", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/settings/email - 403")

    def test_vendor_blocked_roles(self):
        """Vendor should NOT access roles (403)"""
        response = self.session.get(f"{BASE_URL}/api/roles", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/roles - 403")

    def test_vendor_blocked_audit(self):
        """Vendor should NOT access audit (403)"""
        response = self.session.get(f"{BASE_URL}/api/audit/latest", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/audit/latest - 403")

    def test_vendor_blocked_treasury(self):
        """Vendor should NOT access treasury (403)"""
        response = self.session.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/treasury - 403")

    def test_vendor_blocked_clients(self):
        """Vendor should NOT access clients (403)"""
        response = self.session.get(f"{BASE_URL}/api/clients", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/clients - 403")

    def test_vendor_blocked_loans(self):
        """Vendor should NOT access loans (403)"""
        response = self.session.get(f"{BASE_URL}/api/loans", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/loans - 403")

    def test_vendor_blocked_debts(self):
        """Vendor should NOT access debts (403)"""
        response = self.session.get(f"{BASE_URL}/api/debts", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/debts - 403")

    def test_vendor_blocked_psp(self):
        """Vendor should NOT access PSP (403)"""
        response = self.session.get(f"{BASE_URL}/api/psp", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/psp - 403")

    def test_vendor_blocked_lp_accounts(self):
        """Vendor should NOT access LP accounts (403)"""
        response = self.session.get(f"{BASE_URL}/api/lp", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/lp - 403")

    def test_vendor_blocked_reconciliation(self):
        """Vendor should NOT access reconciliation (403)"""
        response = self.session.get(f"{BASE_URL}/api/reconciliation/summary", headers=self.headers)
        assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
        print("✓ Vendor blocked: GET /api/reconciliation/summary - 403")


class TestVendorAllowed:
    """Test that Vendor gets 200 on their allowed endpoints"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # Login as vendor
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": VENDOR_EMAIL,
            "password": VENDOR_PASSWORD
        })
        assert login_resp.status_code == 200, f"Vendor login failed: {login_resp.text}"
        self.token = login_resp.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_vendor_allowed_dashboard(self):
        """Vendor should access dashboard (view permission)"""
        response = self.session.get(f"{BASE_URL}/api/reports/dashboard", headers=self.headers)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        print("✓ Vendor allowed: GET /api/reports/dashboard - 200")

    def test_vendor_allowed_transactions_view(self):
        """Vendor should access transactions list (view permission)"""
        response = self.session.get(f"{BASE_URL}/api/transactions", headers=self.headers)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        print("✓ Vendor allowed: GET /api/transactions - 200")

    def test_vendor_allowed_income_expenses_view(self):
        """Vendor should access income-expenses list (view permission)"""
        response = self.session.get(f"{BASE_URL}/api/income-expenses", headers=self.headers)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        print("✓ Vendor allowed: GET /api/income-expenses - 200")

    def test_vendor_allowed_my_info(self):
        """Vendor should access their own vendor info"""
        response = self.session.get(f"{BASE_URL}/api/vendor/me", headers=self.headers)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        print("✓ Vendor allowed: GET /api/vendor/me - 200")

    def test_vendor_allowed_my_permissions(self):
        """Vendor should access their own permissions"""
        response = self.session.get(f"{BASE_URL}/api/permissions/my", headers=self.headers)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        assert "permissions" in data
        # Verify vendor has expected permissions
        permissions = data.get("permissions", {})
        assert "dashboard" in permissions, "Vendor missing dashboard permission"
        assert "view" in permissions.get("dashboard", []), "Vendor missing dashboard:view"
        print(f"✓ Vendor allowed: GET /api/permissions/my - 200")
        print(f"  Permissions: {permissions}")


class TestUnauthenticatedBlocked:
    """Test that unauthenticated requests get 401 on all protected endpoints"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # NO authentication

    def test_unauth_blocked_dashboard(self):
        """Unauthenticated should NOT access dashboard (401)"""
        response = self.session.get(f"{BASE_URL}/api/reports/dashboard")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated blocked: GET /api/reports/dashboard - 401")

    def test_unauth_blocked_clients(self):
        """Unauthenticated should NOT access clients (401)"""
        response = self.session.get(f"{BASE_URL}/api/clients")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated blocked: GET /api/clients - 401")

    def test_unauth_blocked_transactions(self):
        """Unauthenticated should NOT access transactions (401)"""
        response = self.session.get(f"{BASE_URL}/api/transactions")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated blocked: GET /api/transactions - 401")

    def test_unauth_blocked_users(self):
        """Unauthenticated should NOT access users (401)"""
        response = self.session.get(f"{BASE_URL}/api/users")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated blocked: GET /api/users - 401")

    def test_unauth_blocked_treasury(self):
        """Unauthenticated should NOT access treasury (401)"""
        response = self.session.get(f"{BASE_URL}/api/treasury")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated blocked: GET /api/treasury - 401")

    def test_unauth_blocked_post_transaction(self):
        """POST /api/transactions should require authentication (401)"""
        response = self.session.post(f"{BASE_URL}/api/transactions", json={
            "client_id": "test_client",
            "transaction_type": "deposit",
            "amount": 100,
            "currency": "USD"
        })
        assert response.status_code == 401, f"Expected 401, got {response.status_code}: POST transactions should require auth"
        print("✓ Unauthenticated blocked: POST /api/transactions - 401")

    def test_unauth_blocked_roles(self):
        """Unauthenticated should NOT access roles (401)"""
        response = self.session.get(f"{BASE_URL}/api/roles")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated blocked: GET /api/roles - 401")

    def test_unauth_blocked_logs(self):
        """Unauthenticated should NOT access logs (401)"""
        response = self.session.get(f"{BASE_URL}/api/logs")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("✓ Unauthenticated blocked: GET /api/logs - 401")


class TestImpersonationStillWorks:
    """Test that admin impersonation still works after RBAC migration"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def test_impersonation_endpoint_works(self):
        """Admin should be able to impersonate another user"""
        # Login as admin
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert login_resp.status_code == 200
        admin_token = login_resp.json()["access_token"]
        
        # Get a vendor user to impersonate
        users_resp = self.session.get(
            f"{BASE_URL}/api/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert users_resp.status_code == 200
        users = users_resp.json()
        
        # Find vendor user
        vendor_user = next((u for u in users if u.get("role") == "vendor"), None)
        if not vendor_user:
            pytest.skip("No vendor user found to impersonate")
        
        # Try to impersonate
        impersonate_resp = self.session.post(
            f"{BASE_URL}/api/admin/impersonate/{vendor_user['user_id']}",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert impersonate_resp.status_code == 200, f"Impersonation failed: {impersonate_resp.text}"
        
        imp_data = impersonate_resp.json()
        assert "access_token" in imp_data
        assert "user" in imp_data
        assert imp_data["user"]["role"] == "vendor"
        
        print(f"✓ Impersonation works: Admin can impersonate {vendor_user['email']}")
        
        # Verify impersonated token works
        imp_token = imp_data["access_token"]
        me_resp = self.session.get(
            f"{BASE_URL}/api/auth/me",
            headers={"Authorization": f"Bearer {imp_token}"}
        )
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["user_id"] == vendor_user["user_id"]
        print(f"✓ Impersonated token works: /auth/me returns {me_data['email']}")


class TestDashboardPermission:
    """Test that Dashboard API now requires proper permission"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def test_dashboard_requires_permission(self):
        """Dashboard stats requires dashboard:view permission"""
        # Login as admin
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        admin_token = login_resp.json()["access_token"]
        
        # Verify admin can access
        response = self.session.get(
            f"{BASE_URL}/api/reports/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        print("✓ Dashboard requires permission: Admin with dashboard:view gets 200")
        
        # Verify vendor (who has dashboard:view) can also access
        vendor_login = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": VENDOR_EMAIL,
            "password": VENDOR_PASSWORD
        })
        vendor_token = vendor_login.json()["access_token"]
        
        response = self.session.get(
            f"{BASE_URL}/api/reports/dashboard",
            headers={"Authorization": f"Bearer {vendor_token}"}
        )
        assert response.status_code == 200
        print("✓ Dashboard requires permission: Vendor with dashboard:view gets 200")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
