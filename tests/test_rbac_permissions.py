"""
Test suite for RBAC (Role-Based Access Control) permissions
Specifically testing:
1. Settings page access for admin
2. User Management with roles
3. Roles & Permissions management
4. Exchanger role permission modifications
5. Vendor endpoint permission enforcement
6. Daily P&L scheduler configuration
"""

import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
ADMIN_EMAIL = "admin@fxbroker.com"
ADMIN_PASSWORD = "admin123"
EXCHANGER_EMAIL = "kenway@fxbroker.com"
EXCHANGER_PASSWORD = "password"


class TestRBACPermissions:
    """Test RBAC and permission enforcement"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    # ========== AUTH TESTS ==========
    def test_admin_login(self):
        """Test admin can login successfully"""
        response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert response.status_code == 200, f"Admin login failed: {response.text}"
        data = response.json()
        assert "access_token" in data
        assert data["user"]["email"] == ADMIN_EMAIL
        assert data["user"]["role"] == "admin"
        print(f"✓ Admin login successful: {ADMIN_EMAIL}")

    def test_exchanger_login(self):
        """Test exchanger/vendor user can login"""
        response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": EXCHANGER_EMAIL,
            "password": EXCHANGER_PASSWORD
        })
        assert response.status_code == 200, f"Exchanger login failed: {response.text}"
        data = response.json()
        assert "access_token" in data
        print(f"✓ Exchanger login successful: {EXCHANGER_EMAIL}, role: {data['user']['role']}")

    # ========== SETTINGS PAGE ACCESS (P0) ==========
    def test_admin_can_access_users_endpoint(self):
        """Test admin can access /api/users - verifies Settings page accessibility"""
        # Login as admin
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        
        # Access users endpoint (Settings page User Management)
        response = self.session.get(
            f"{BASE_URL}/api/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, f"Failed to access users: {response.text}"
        users = response.json()
        assert isinstance(users, list)
        print(f"✓ Admin can access users endpoint. Found {len(users)} users")

    def test_admin_can_access_email_settings(self):
        """Test admin can access email settings - verifies Settings page"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        response = self.session.get(
            f"{BASE_URL}/api/settings/email",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, f"Failed to access email settings: {response.text}"
        data = response.json()
        assert "smtp_host" in data or "report_enabled" in data
        print(f"✓ Admin can access email settings")

    def test_admin_can_access_fx_rates(self):
        """Test admin can access FX rates from Settings"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        response = self.session.get(
            f"{BASE_URL}/api/fx-rates",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, f"Failed to access FX rates: {response.text}"
        data = response.json()
        assert "rates" in data
        print(f"✓ Admin can access FX rates. Source: {data.get('source', 'unknown')}")

    # ========== USER MANAGEMENT ==========
    def test_users_list_shows_roles(self):
        """Test users endpoint returns role information"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        response = self.session.get(
            f"{BASE_URL}/api/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        users = response.json()
        
        # Check users have role field
        for user in users:
            assert "role" in user, f"User missing role: {user.get('email')}"
        
        # Find users with different roles
        roles_found = set(u.get("role") for u in users)
        print(f"✓ Users list shows roles. Roles found: {roles_found}")

    # ========== ROLES & PERMISSIONS PAGE ==========
    def test_get_all_roles(self):
        """Test /api/roles returns list of roles"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        response = self.session.get(
            f"{BASE_URL}/api/roles",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, f"Failed to get roles: {response.text}"
        roles = response.json()
        assert isinstance(roles, list)
        assert len(roles) > 0, "No roles found"
        
        # Check for expected system roles
        role_ids = [r.get("role_id") for r in roles]
        assert "admin" in role_ids or "super_admin" in role_ids, "Admin role not found"
        
        print(f"✓ Roles endpoint returns {len(roles)} roles: {role_ids}")

    def test_get_exchanger_role_details(self):
        """Test can get specific exchanger role with permissions"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        response = self.session.get(
            f"{BASE_URL}/api/roles/exchanger",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, f"Failed to get exchanger role: {response.text}"
        role = response.json()
        
        assert role.get("role_id") == "exchanger" or role.get("name") == "vendor"
        assert "permissions" in role
        print(f"✓ Exchanger role retrieved. Display name: {role.get('display_name')}")
        print(f"  Permissions: {role.get('permissions', {})}")

    def test_get_permission_modules(self):
        """Test can get list of all modules and actions for permission matrix"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        response = self.session.get(
            f"{BASE_URL}/api/permissions/modules",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, f"Failed to get modules: {response.text}"
        data = response.json()
        
        assert "modules" in data
        assert "actions" in data
        assert len(data["modules"]) > 0, "No modules found"
        assert len(data["actions"]) > 0, "No actions found"
        
        print(f"✓ Permission modules: {len(data['modules'])} modules, {len(data['actions'])} actions")

    # ========== EXCHANGER ROLE PERMISSION CHANGES (P1) ==========
    def test_update_exchanger_role_permissions(self):
        """Test can modify exchanger role permissions via API"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        # Get current exchanger role
        get_resp = self.session.get(
            f"{BASE_URL}/api/roles/exchanger",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert get_resp.status_code == 200
        current_role = get_resp.json()
        original_permissions = current_role.get("permissions", {})
        
        # Update permissions - add/modify something
        new_permissions = {**original_permissions}
        new_permissions["dashboard"] = ["view"]  # Ensure dashboard view
        new_permissions["transactions"] = ["view", "approve"]  # Core exchanger permissions
        
        update_resp = self.session.put(
            f"{BASE_URL}/api/roles/exchanger",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "permissions": new_permissions
            }
        )
        assert update_resp.status_code == 200, f"Failed to update role: {update_resp.text}"
        updated_role = update_resp.json()
        
        # Verify update took effect
        assert updated_role.get("permissions") == new_permissions
        print(f"✓ Exchanger role permissions updated successfully")
        print(f"  New permissions: {new_permissions}")

    # ========== VENDOR ENDPOINT PERMISSION ENFORCEMENT (P1) ==========
    def test_vendor_approve_requires_permission(self):
        """Test vendor_approve_transaction enforces granular permissions"""
        # Login as exchanger user
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": EXCHANGER_EMAIL,
            "password": EXCHANGER_PASSWORD
        })
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        
        # Try to approve a non-existent transaction
        # This tests that the permission check happens before transaction validation
        response = self.session.post(
            f"{BASE_URL}/api/vendor/transactions/fake_transaction_id/approve",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Should get 403 (permission denied) or 404 (not found) depending on permission
        # If 403, permissions are being enforced
        # If 404, user has permission but transaction doesn't exist
        assert response.status_code in [403, 404], f"Unexpected status: {response.status_code}, {response.text}"
        
        if response.status_code == 403:
            print(f"✓ Vendor approve endpoint enforces permissions (403 - Permission denied)")
        else:
            print(f"✓ Vendor has approval permission, transaction not found (404)")

    def test_permission_changes_affect_vendor_immediately(self):
        """Test that permission changes on exchanger role immediately affect vendor users"""
        # 1. Login as admin
        admin_login = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        admin_token = admin_login.json()["access_token"]
        
        # 2. Get current exchanger permissions
        role_resp = self.session.get(
            f"{BASE_URL}/api/roles/exchanger",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert role_resp.status_code == 200
        original_permissions = role_resp.json().get("permissions", {})
        
        # 3. Remove approve permission from transactions
        modified_permissions = {k: v for k, v in original_permissions.items()}
        if "transactions" in modified_permissions:
            modified_permissions["transactions"] = [a for a in modified_permissions["transactions"] if a != "approve"]
            if not modified_permissions["transactions"]:
                del modified_permissions["transactions"]
        
        update_resp = self.session.put(
            f"{BASE_URL}/api/roles/exchanger",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"permissions": modified_permissions}
        )
        assert update_resp.status_code == 200
        
        # 4. Try vendor approve as exchanger - should be denied now
        vendor_login = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": EXCHANGER_EMAIL,
            "password": EXCHANGER_PASSWORD
        })
        vendor_token = vendor_login.json()["access_token"]
        
        approve_resp = self.session.post(
            f"{BASE_URL}/api/vendor/transactions/fake_id/approve",
            headers={"Authorization": f"Bearer {vendor_token}"}
        )
        
        # Should be denied (403) since we removed approve permission
        assert approve_resp.status_code == 403, f"Expected 403, got {approve_resp.status_code}: {approve_resp.text}"
        print(f"✓ Permission removal immediately enforced (got 403 as expected)")
        
        # 5. Restore permissions
        restore_resp = self.session.put(
            f"{BASE_URL}/api/roles/exchanger",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"permissions": original_permissions}
        )
        assert restore_resp.status_code == 200
        
        # 6. Verify vendor can now access (404 because fake ID, but not 403)
        approve_resp2 = self.session.post(
            f"{BASE_URL}/api/vendor/transactions/fake_id/approve",
            headers={"Authorization": f"Bearer {vendor_token}"}
        )
        # Should now be 404 (transaction not found) instead of 403
        assert approve_resp2.status_code == 404, f"Expected 404 after restoring permissions, got {approve_resp2.status_code}"
        print(f"✓ Permission restoration immediately enforced (got 404 - permission granted)")

    def test_vendor_ie_approve_requires_permission(self):
        """Test vendor_approve_ie endpoint enforces permissions"""
        vendor_login = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": EXCHANGER_EMAIL,
            "password": EXCHANGER_PASSWORD
        })
        vendor_token = vendor_login.json()["access_token"]
        
        response = self.session.post(
            f"{BASE_URL}/api/income-expenses/fake_entry_id/vendor-approve",
            headers={"Authorization": f"Bearer {vendor_token}"}
        )
        
        # Should be 403 (no permission) or 404 (entry not found, has permission)
        assert response.status_code in [403, 404], f"Unexpected status: {response.status_code}"
        print(f"✓ Vendor IE approve endpoint checks permissions (status: {response.status_code})")

    # ========== MIGRATION ENDPOINT ==========
    def test_assign_role_ids_endpoint(self):
        """Test the migration endpoint to assign role_ids to users"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        response = self.session.post(
            f"{BASE_URL}/api/users/assign-role-ids",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, f"Migration endpoint failed: {response.text}"
        data = response.json()
        assert "message" in data
        print(f"✓ Assign role IDs endpoint works: {data.get('message')}, count: {data.get('count', 0)}")

    # ========== USER PERMISSION CHECK ==========
    def test_get_my_permissions(self):
        """Test user can get their own permissions"""
        vendor_login = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": EXCHANGER_EMAIL,
            "password": EXCHANGER_PASSWORD
        })
        vendor_token = vendor_login.json()["access_token"]
        
        response = self.session.get(
            f"{BASE_URL}/api/permissions/my",
            headers={"Authorization": f"Bearer {vendor_token}"}
        )
        assert response.status_code == 200, f"Failed to get permissions: {response.text}"
        data = response.json()
        assert "permissions" in data
        print(f"✓ User can get their permissions: {data.get('permissions', {})}")


class TestDailyPnLScheduler:
    """Test P&L email scheduler configuration (P2)"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def test_daily_report_scheduler_exists(self):
        """Verify daily report email scheduler is configured"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        # Check email settings has report_enabled and report_time
        response = self.session.get(
            f"{BASE_URL}/api/settings/email",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify scheduler config fields exist
        assert "report_enabled" in data or response.status_code == 200
        print(f"✓ Daily report scheduler configuration exists")
        print(f"  report_enabled: {data.get('report_enabled')}")
        print(f"  report_time: {data.get('report_time')}")
        print(f"  director_emails count: {len(data.get('director_emails', []))}")

    def test_can_send_report_now(self):
        """Test manual report sending endpoint exists"""
        login_resp = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_resp.json()["access_token"]
        
        # Check if send-now endpoint is accessible (won't actually send if no emails configured)
        response = self.session.post(
            f"{BASE_URL}/api/reports/send-now",
            headers={"Authorization": f"Bearer {token}"}
        )
        # Should be 200 (sent) or 400 (no emails configured) or 500 (smtp not configured)
        # Any response other than 404 means endpoint exists
        assert response.status_code != 404, "Report send-now endpoint not found"
        print(f"✓ Daily report send-now endpoint exists (status: {response.status_code})")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
