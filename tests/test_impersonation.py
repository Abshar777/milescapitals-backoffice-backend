"""
Test module for Admin Impersonation Feature - Miles Capitals FX Broker Back-Office
Tests: 
1. POST /api/admin/impersonate/{user_id} - Impersonate a sub-user
2. POST /api/admin/impersonate/{user_id} - Block admin-role impersonation (403)
3. POST /api/admin/impersonate/{user_id} - Block non-admin users from impersonating
4. POST /api/admin/stop-impersonate - Log end time of impersonation
5. GET /api/admin/impersonation-logs - Retrieve audit logs
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL')

class TestImpersonation:
    """Tests for the Admin Impersonation feature"""
    
    admin_token = None
    admin_user_id = None
    vendor_token = None
    vendor_user_id = None
    impersonation_log_id = None
    impersonated_token = None
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup: Login as admin and vendor to get tokens"""
        # Admin login
        admin_response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "admin123"
        })
        assert admin_response.status_code == 200, f"Admin login failed: {admin_response.text}"
        admin_data = admin_response.json()
        TestImpersonation.admin_token = admin_data["access_token"]
        TestImpersonation.admin_user_id = admin_data["user"]["user_id"]
        
        # Vendor login
        vendor_response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "kenway@fxbroker.com",
            "password": "password"
        })
        assert vendor_response.status_code == 200, f"Vendor login failed: {vendor_response.text}"
        vendor_data = vendor_response.json()
        TestImpersonation.vendor_token = vendor_data["access_token"]
        TestImpersonation.vendor_user_id = vendor_data["user"]["user_id"]
    
    def test_01_impersonate_vendor_success(self):
        """Test: Admin can successfully impersonate a vendor user"""
        # Get the vendor user ID first
        response = requests.post(
            f"{BASE_URL}/api/admin/impersonate/{TestImpersonation.vendor_user_id}",
            headers={"Authorization": f"Bearer {TestImpersonation.admin_token}"}
        )
        
        assert response.status_code == 200, f"Impersonate failed: {response.text}"
        data = response.json()
        
        # Validate response structure
        assert "access_token" in data, "Missing access_token in response"
        assert "impersonation_log_id" in data, "Missing impersonation_log_id"
        assert "user" in data, "Missing user object in response"
        
        # Validate user data
        assert data["user"]["user_id"] == TestImpersonation.vendor_user_id
        assert data["user"]["role"] == "vendor"
        
        # Store for later tests
        TestImpersonation.impersonation_log_id = data["impersonation_log_id"]
        TestImpersonation.impersonated_token = data["access_token"]
        
        print(f"✓ Successfully impersonated vendor user: {data['user']['name']}")
        print(f"✓ Impersonation log ID: {data['impersonation_log_id']}")
    
    def test_02_impersonated_token_works(self):
        """Test: Impersonated token can be used to access API as the target user"""
        if not TestImpersonation.impersonated_token:
            pytest.skip("No impersonated token available")
        
        # Use impersonated token to get current user
        response = requests.get(
            f"{BASE_URL}/api/auth/me",
            headers={"Authorization": f"Bearer {TestImpersonation.impersonated_token}"}
        )
        
        assert response.status_code == 200, f"Auth/me failed with impersonated token: {response.text}"
        data = response.json()
        
        # Should return the vendor user, not admin
        assert data["user_id"] == TestImpersonation.vendor_user_id
        assert data["role"] == "vendor"
        print(f"✓ Impersonated token works - logged in as: {data['name']} ({data['role']})")
    
    def test_03_block_impersonate_admin(self):
        """Test: Admin cannot impersonate another admin - should return 403"""
        # Try to impersonate the admin user
        response = requests.post(
            f"{BASE_URL}/api/admin/impersonate/{TestImpersonation.admin_user_id}",
            headers={"Authorization": f"Bearer {TestImpersonation.admin_token}"}
        )
        
        assert response.status_code == 403, f"Expected 403 but got {response.status_code}"
        data = response.json()
        assert "Cannot impersonate another Admin" in data.get("detail", "")
        print("✓ Correctly blocked impersonation of admin user (403)")
    
    def test_04_non_admin_cannot_impersonate(self):
        """Test: Non-admin users cannot use impersonation endpoint"""
        # Try impersonating with vendor token
        response = requests.post(
            f"{BASE_URL}/api/admin/impersonate/{TestImpersonation.admin_user_id}",
            headers={"Authorization": f"Bearer {TestImpersonation.vendor_token}"}
        )
        
        assert response.status_code == 403, f"Expected 403 but got {response.status_code}"
        print("✓ Non-admin correctly blocked from impersonating (403)")
    
    def test_05_stop_impersonation(self):
        """Test: Stop impersonation logs the end time"""
        if not TestImpersonation.impersonated_token:
            pytest.skip("No impersonated token available")
        
        response = requests.post(
            f"{BASE_URL}/api/admin/stop-impersonate",
            headers={"Authorization": f"Bearer {TestImpersonation.impersonated_token}"},
            json={"log_id": TestImpersonation.impersonation_log_id}
        )
        
        assert response.status_code == 200, f"Stop impersonate failed: {response.text}"
        data = response.json()
        assert data.get("message") == "Impersonation ended"
        print("✓ Impersonation stopped successfully")
    
    def test_06_get_impersonation_logs(self):
        """Test: Admin can retrieve impersonation audit logs"""
        response = requests.get(
            f"{BASE_URL}/api/admin/impersonation-logs",
            headers={"Authorization": f"Bearer {TestImpersonation.admin_token}"}
        )
        
        assert response.status_code == 200, f"Get logs failed: {response.text}"
        data = response.json()
        
        # Should be a list
        assert isinstance(data, list), "Expected list of logs"
        
        # Find our impersonation log
        if TestImpersonation.impersonation_log_id:
            found_log = None
            for log in data:
                if log.get("log_id") == TestImpersonation.impersonation_log_id:
                    found_log = log
                    break
            
            if found_log:
                # Verify log structure
                assert "admin_id" in found_log
                assert "admin_name" in found_log
                assert "user_id" in found_log
                assert "user_name" in found_log
                assert "login_time" in found_log
                assert "logout_time" in found_log, "Logout time should be set after stop"
                assert found_log["status"] == "ended", "Status should be 'ended' after stop"
                print(f"✓ Found impersonation log with correct structure")
                print(f"  - Admin: {found_log['admin_name']} ({found_log['admin_email']})")
                print(f"  - Target: {found_log['user_name']} ({found_log['user_role']})")
                print(f"  - Status: {found_log['status']}")
        
        print(f"✓ Retrieved {len(data)} impersonation log entries")
    
    def test_07_non_admin_cannot_view_logs(self):
        """Test: Non-admin users cannot view impersonation logs"""
        response = requests.get(
            f"{BASE_URL}/api/admin/impersonation-logs",
            headers={"Authorization": f"Bearer {TestImpersonation.vendor_token}"}
        )
        
        assert response.status_code == 403, f"Expected 403 but got {response.status_code}"
        print("✓ Non-admin correctly blocked from viewing logs (403)")
    
    def test_08_impersonate_nonexistent_user(self):
        """Test: Cannot impersonate a non-existent user"""
        response = requests.post(
            f"{BASE_URL}/api/admin/impersonate/user_nonexistent123",
            headers={"Authorization": f"Bearer {TestImpersonation.admin_token}"}
        )
        
        assert response.status_code == 404, f"Expected 404 but got {response.status_code}"
        print("✓ Correctly returned 404 for non-existent user")


class TestImpersonationIntegration:
    """Integration tests for the impersonation flow"""
    
    def test_full_impersonation_flow(self):
        """Test: Complete impersonation workflow from start to finish"""
        # 1. Admin login
        admin_login = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "admin123"
        })
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]
        admin_name = admin_login.json()["user"]["name"]
        
        # 2. Get list of users to find a non-admin user
        users_response = requests.get(
            f"{BASE_URL}/api/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert users_response.status_code == 200
        users = users_response.json()
        
        # Find a non-admin user
        target_user = None
        for u in users:
            if u.get("role") != "admin" and u.get("is_active") != False:
                target_user = u
                break
        
        if not target_user:
            pytest.skip("No non-admin user available to impersonate")
        
        print(f"1. Admin '{admin_name}' logged in")
        print(f"2. Found target user: {target_user['name']} ({target_user['role']})")
        
        # 3. Start impersonation
        impersonate_response = requests.post(
            f"{BASE_URL}/api/admin/impersonate/{target_user['user_id']}",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert impersonate_response.status_code == 200
        imp_data = impersonate_response.json()
        imp_token = imp_data["access_token"]
        log_id = imp_data["impersonation_log_id"]
        
        print(f"3. Started impersonating {target_user['name']}")
        
        # 4. Verify identity with impersonated token
        me_response = requests.get(
            f"{BASE_URL}/api/auth/me",
            headers={"Authorization": f"Bearer {imp_token}"}
        )
        assert me_response.status_code == 200
        assert me_response.json()["user_id"] == target_user["user_id"]
        
        print(f"4. Verified impersonated identity")
        
        # 5. Stop impersonation
        stop_response = requests.post(
            f"{BASE_URL}/api/admin/stop-impersonate",
            headers={"Authorization": f"Bearer {imp_token}"},
            json={"log_id": log_id}
        )
        assert stop_response.status_code == 200
        
        print(f"5. Stopped impersonation")
        
        # 6. Verify log was updated
        logs_response = requests.get(
            f"{BASE_URL}/api/admin/impersonation-logs",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert logs_response.status_code == 200
        logs = logs_response.json()
        
        found_log = next((l for l in logs if l.get("log_id") == log_id), None)
        assert found_log is not None, "Log not found"
        assert found_log["status"] == "ended"
        assert found_log["logout_time"] is not None
        
        print(f"6. Verified audit log was updated with end time")
        print("✓ Full impersonation workflow completed successfully")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
