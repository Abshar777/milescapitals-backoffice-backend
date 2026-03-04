"""
Vendor Transactions Feature Tests

Tests for:
1. GET /api/vendor/transactions - returns all transactions (with filters)
2. GET /api/vendor/transactions/export/excel - export to Excel
3. GET /api/vendor/transactions/export/pdf - export to PDF
4. Non-vendor users blocked (403)
"""

import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
VENDOR_EMAIL = "kenway@fxbroker.com"
VENDOR_PASSWORD = "password"
ADMIN_EMAIL = "admin@fxbroker.com"
ADMIN_PASSWORD = "admin123"


class TestVendorTransactionsEndpoints:
    """Tests for vendor transactions endpoints"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup: Get tokens for vendor and admin"""
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        
        # Login as vendor
        vendor_response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": VENDOR_EMAIL,
            "password": VENDOR_PASSWORD
        })
        if vendor_response.status_code == 200:
            self.vendor_token = vendor_response.json().get("access_token")
        else:
            pytest.skip(f"Could not login as vendor: {vendor_response.status_code}")
        
        # Login as admin
        admin_response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        if admin_response.status_code == 200:
            self.admin_token = admin_response.json().get("access_token")
        else:
            pytest.skip(f"Could not login as admin: {admin_response.status_code}")
    
    # ---------------------------
    # GET /api/vendor/transactions
    # ---------------------------
    
    def test_vendor_get_all_transactions_success(self):
        """Vendor can get all assigned transactions (not just pending)"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        data = response.json()
        assert isinstance(data, list), "Response should be a list"
        print(f"✓ Vendor transactions endpoint returned {len(data)} transactions")
    
    def test_vendor_transactions_filter_by_status_pending(self):
        """Vendor can filter transactions by status=pending"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions?status=pending",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert isinstance(data, list)
        # All returned transactions should have status=pending (or empty if none)
        for tx in data:
            assert tx.get("status") == "pending", f"Transaction {tx.get('transaction_id')} should be pending, got {tx.get('status')}"
        print(f"✓ Filter by status=pending returned {len(data)} transactions")
    
    def test_vendor_transactions_filter_by_status_approved(self):
        """Vendor can filter transactions by status=approved"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions?status=approved",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert isinstance(data, list)
        for tx in data:
            assert tx.get("status") == "approved", f"Transaction should be approved"
        print(f"✓ Filter by status=approved returned {len(data)} transactions")
    
    def test_vendor_transactions_filter_by_status_rejected(self):
        """Vendor can filter transactions by status=rejected"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions?status=rejected",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert isinstance(data, list)
        for tx in data:
            assert tx.get("status") == "rejected", f"Transaction should be rejected"
        print(f"✓ Filter by status=rejected returned {len(data)} transactions")
    
    def test_vendor_transactions_filter_by_status_completed(self):
        """Vendor can filter transactions by status=completed"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions?status=completed",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert isinstance(data, list)
        for tx in data:
            assert tx.get("status") == "completed", f"Transaction should be completed"
        print(f"✓ Filter by status=completed returned {len(data)} transactions")
    
    def test_vendor_transactions_filter_by_type_deposit(self):
        """Vendor can filter transactions by transaction_type=deposit"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions?transaction_type=deposit",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert isinstance(data, list)
        for tx in data:
            assert tx.get("transaction_type") == "deposit", f"Transaction should be deposit type"
        print(f"✓ Filter by transaction_type=deposit returned {len(data)} transactions")
    
    def test_vendor_transactions_filter_by_type_withdrawal(self):
        """Vendor can filter transactions by transaction_type=withdrawal"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions?transaction_type=withdrawal",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert isinstance(data, list)
        for tx in data:
            assert tx.get("transaction_type") == "withdrawal", f"Transaction should be withdrawal type"
        print(f"✓ Filter by transaction_type=withdrawal returned {len(data)} transactions")
    
    def test_vendor_transactions_filter_by_date_range(self):
        """Vendor can filter transactions by date range"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions?date_from=2025-01-01&date_to=2025-12-31",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert isinstance(data, list)
        # All returned transactions should be within date range
        for tx in data:
            created_at = tx.get("created_at", "")
            if created_at:
                assert created_at >= "2025-01-01", f"Transaction date {created_at} should be >= 2025-01-01"
                assert created_at <= "2025-12-31T23:59:59", f"Transaction date should be <= 2025-12-31"
        print(f"✓ Filter by date range returned {len(data)} transactions")
    
    def test_vendor_transactions_combined_filters(self):
        """Vendor can use multiple filters together"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions?status=pending&transaction_type=deposit",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert isinstance(data, list)
        for tx in data:
            assert tx.get("status") == "pending"
            assert tx.get("transaction_type") == "deposit"
        print(f"✓ Combined filters returned {len(data)} transactions")
    
    # ---------------------------
    # Export endpoints
    # ---------------------------
    
    def test_vendor_export_excel_success(self):
        """Vendor can export transactions to Excel"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions/export/excel",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        # Check content type
        content_type = response.headers.get("content-type", "")
        assert "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in content_type or "application/octet-stream" in content_type, f"Expected Excel content type, got {content_type}"
        
        # Check content disposition (filename)
        content_disposition = response.headers.get("content-disposition", "")
        assert "attachment" in content_disposition, f"Expected attachment disposition, got {content_disposition}"
        assert ".xlsx" in content_disposition, f"Expected .xlsx filename in {content_disposition}"
        
        # Check response has content
        assert len(response.content) > 0, "Excel file should not be empty"
        print(f"✓ Excel export returned {len(response.content)} bytes")
    
    def test_vendor_export_excel_with_filters(self):
        """Vendor can export filtered transactions to Excel"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions/export/excel?status=pending&transaction_type=deposit",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert len(response.content) > 0, "Excel file should not be empty"
        print(f"✓ Filtered Excel export returned {len(response.content)} bytes")
    
    def test_vendor_export_pdf_success(self):
        """Vendor can export transactions to PDF"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions/export/pdf",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        # Check content type
        content_type = response.headers.get("content-type", "")
        assert "application/pdf" in content_type, f"Expected PDF content type, got {content_type}"
        
        # Check content disposition (filename)
        content_disposition = response.headers.get("content-disposition", "")
        assert "attachment" in content_disposition, f"Expected attachment disposition, got {content_disposition}"
        assert ".pdf" in content_disposition, f"Expected .pdf filename in {content_disposition}"
        
        # Check response has content
        assert len(response.content) > 0, "PDF file should not be empty"
        
        # Check PDF magic bytes (PDF files start with %PDF)
        assert response.content[:4] == b'%PDF', "Response should be a valid PDF file"
        print(f"✓ PDF export returned {len(response.content)} bytes")
    
    def test_vendor_export_pdf_with_filters(self):
        """Vendor can export filtered transactions to PDF"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions/export/pdf?status=approved&date_from=2025-01-01",
            headers={"Authorization": f"Bearer {self.vendor_token}"}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert len(response.content) > 0, "PDF file should not be empty"
        assert response.content[:4] == b'%PDF', "Response should be a valid PDF file"
        print(f"✓ Filtered PDF export returned {len(response.content)} bytes")
    
    # ---------------------------
    # Access control tests
    # ---------------------------
    
    def test_non_vendor_cannot_access_vendor_transactions(self):
        """Admin user (non-vendor) cannot access vendor-specific transactions endpoint"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        # Admin is not a vendor, should get 403
        assert response.status_code == 403, f"Expected 403 for non-vendor, got {response.status_code}"
        print(f"✓ Non-vendor correctly blocked from /vendor/transactions")
    
    def test_non_vendor_cannot_export_excel(self):
        """Admin user (non-vendor) cannot access vendor Excel export"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions/export/excel",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        assert response.status_code == 403, f"Expected 403 for non-vendor, got {response.status_code}"
        print(f"✓ Non-vendor correctly blocked from Excel export")
    
    def test_non_vendor_cannot_export_pdf(self):
        """Admin user (non-vendor) cannot access vendor PDF export"""
        response = self.session.get(
            f"{BASE_URL}/api/vendor/transactions/export/pdf",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        assert response.status_code == 403, f"Expected 403 for non-vendor, got {response.status_code}"
        print(f"✓ Non-vendor correctly blocked from PDF export")
    
    def test_unauthenticated_cannot_access_vendor_transactions(self):
        """Unauthenticated user cannot access vendor transactions"""
        response = self.session.get(f"{BASE_URL}/api/vendor/transactions")
        assert response.status_code == 401, f"Expected 401 for unauthenticated, got {response.status_code}"
        print(f"✓ Unauthenticated correctly blocked from /vendor/transactions")
    
    def test_unauthenticated_cannot_export_excel(self):
        """Unauthenticated user cannot export Excel"""
        response = self.session.get(f"{BASE_URL}/api/vendor/transactions/export/excel")
        assert response.status_code == 401, f"Expected 401 for unauthenticated, got {response.status_code}"
        print(f"✓ Unauthenticated correctly blocked from Excel export")
    
    def test_unauthenticated_cannot_export_pdf(self):
        """Unauthenticated user cannot export PDF"""
        response = self.session.get(f"{BASE_URL}/api/vendor/transactions/export/pdf")
        assert response.status_code == 401, f"Expected 401 for unauthenticated, got {response.status_code}"
        print(f"✓ Unauthenticated correctly blocked from PDF export")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
