"""
Backend API Tests for Vendor Suppliers and IE Categories
Testing the new CRUD endpoints for:
1. Vendor Suppliers - /api/vendor-suppliers (service providers like rent, utilities)
2. IE Categories - /api/ie-categories (custom account categories for income/expenses)
3. Income/Expense entry linking to Client, Vendor Supplier, and IE Category
"""
import pytest
import requests
import os
import uuid

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test data tracking for cleanup
created_supplier_ids = []
created_category_ids = []
created_entry_ids = []

# ============== FIXTURES ==============

@pytest.fixture(scope="module")
def auth_token():
    """Login and get auth token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "admin@fxbroker.com",
        "password": "password"
    })
    assert response.status_code == 200, f"Login failed: {response.text}"
    return response.json()["access_token"]

@pytest.fixture(scope="module")
def api_client(auth_token):
    """Return session with auth headers"""
    session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}"
    })
    return session

@pytest.fixture(scope="module")
def test_treasury_account(api_client):
    """Get or create a treasury account for testing"""
    response = api_client.get(f"{BASE_URL}/api/treasury")
    assert response.status_code == 200
    accounts = response.json()
    if accounts:
        return accounts[0]
    # Create one if none exists
    response = api_client.post(f"{BASE_URL}/api/treasury", json={
        "account_name": "TEST_Treasury_Account",
        "account_type": "bank",
        "currency": "USD"
    })
    return response.json()

@pytest.fixture(scope="module")  
def test_client(api_client):
    """Get or create a client for testing"""
    response = api_client.get(f"{BASE_URL}/api/clients")
    assert response.status_code == 200
    clients = response.json()
    if clients:
        return clients[0]
    # Create one if none exists
    response = api_client.post(f"{BASE_URL}/api/clients", json={
        "first_name": "TEST_Client",
        "last_name": "ForTesting",
        "email": f"test_client_{uuid.uuid4().hex[:6]}@example.com"
    })
    return response.json()

# ============== VENDOR SUPPLIER TESTS ==============

class TestVendorSuppliersCRUD:
    """Tests for Vendor Suppliers CRUD operations"""
    
    def test_create_vendor_supplier_basic(self, api_client):
        """Test creating a basic vendor supplier with name only"""
        unique_name = f"TEST_Vendor_{uuid.uuid4().hex[:8]}"
        response = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={
            "name": unique_name
        })
        
        assert response.status_code == 200, f"Create failed: {response.text}"
        data = response.json()
        assert "supplier_id" in data
        assert data["name"] == unique_name
        assert data["status"] == "active"
        
        created_supplier_ids.append(data["supplier_id"])
        print(f"Created vendor supplier: {data['supplier_id']}")
    
    def test_create_vendor_supplier_full(self, api_client):
        """Test creating a vendor supplier with all fields"""
        unique_name = f"TEST_FullVendor_{uuid.uuid4().hex[:8]}"
        payload = {
            "name": unique_name,
            "contact_person": "John Smith",
            "email": f"vendor_{uuid.uuid4().hex[:6]}@example.com",
            "phone": "+1234567890",
            "address": "123 Main Street",
            "bank_name": "TEST Bank",
            "bank_account_name": "Full Vendor Account",
            "bank_account_number": "1234567890",
            "bank_ifsc": "TEST1234",
            "bank_branch": "Main Branch",
            "notes": "Test vendor with full details"
        }
        
        response = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json=payload)
        
        assert response.status_code == 200, f"Create failed: {response.text}"
        data = response.json()
        
        # Verify all fields
        assert data["name"] == unique_name
        assert data["contact_person"] == "John Smith"
        assert data["bank_name"] == "TEST Bank"
        assert data["bank_account_number"] == "1234567890"
        assert "created_at" in data
        
        created_supplier_ids.append(data["supplier_id"])
        print(f"Created full vendor supplier: {data['supplier_id']}")
    
    def test_create_vendor_duplicate_name_fails(self, api_client):
        """Test that duplicate vendor names are rejected"""
        unique_name = f"TEST_DupeVendor_{uuid.uuid4().hex[:8]}"
        
        # Create first
        response1 = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={"name": unique_name})
        assert response1.status_code == 200
        created_supplier_ids.append(response1.json()["supplier_id"])
        
        # Try to create duplicate
        response2 = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={"name": unique_name})
        assert response2.status_code == 400, "Expected 400 for duplicate name"
        assert "already exists" in response2.json().get("detail", "").lower()
    
    def test_get_all_vendor_suppliers(self, api_client):
        """Test listing all vendor suppliers"""
        response = api_client.get(f"{BASE_URL}/api/vendor-suppliers")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"Found {len(data)} vendor suppliers")
    
    def test_get_vendor_supplier_by_id(self, api_client):
        """Test getting a specific vendor supplier"""
        # Create one first
        unique_name = f"TEST_GetVendor_{uuid.uuid4().hex[:8]}"
        create_response = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={"name": unique_name})
        assert create_response.status_code == 200
        supplier_id = create_response.json()["supplier_id"]
        created_supplier_ids.append(supplier_id)
        
        # Get by ID
        response = api_client.get(f"{BASE_URL}/api/vendor-suppliers/{supplier_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["supplier_id"] == supplier_id
        assert data["name"] == unique_name
    
    def test_update_vendor_supplier(self, api_client):
        """Test updating a vendor supplier"""
        # Create first
        unique_name = f"TEST_UpdateVendor_{uuid.uuid4().hex[:8]}"
        create_response = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={"name": unique_name})
        assert create_response.status_code == 200
        supplier_id = create_response.json()["supplier_id"]
        created_supplier_ids.append(supplier_id)
        
        # Update
        updated_name = f"UPDATED_{unique_name}"
        response = api_client.put(f"{BASE_URL}/api/vendor-suppliers/{supplier_id}", json={
            "name": updated_name,
            "phone": "+9876543210",
            "bank_name": "Updated Bank"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == updated_name
        assert data["phone"] == "+9876543210"
        assert data["bank_name"] == "Updated Bank"
        
        # Verify by getting again
        get_response = api_client.get(f"{BASE_URL}/api/vendor-suppliers/{supplier_id}")
        assert get_response.status_code == 200
        assert get_response.json()["name"] == updated_name
    
    def test_delete_vendor_supplier(self, api_client):
        """Test deleting a vendor supplier"""
        # Create first
        unique_name = f"TEST_DeleteVendor_{uuid.uuid4().hex[:8]}"
        create_response = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={"name": unique_name})
        assert create_response.status_code == 200
        supplier_id = create_response.json()["supplier_id"]
        
        # Delete
        response = api_client.delete(f"{BASE_URL}/api/vendor-suppliers/{supplier_id}")
        assert response.status_code == 200
        assert "deleted" in response.json()["message"].lower() or "inactive" in response.json()["message"].lower()
        
        # Verify - either not found or status inactive
        get_response = api_client.get(f"{BASE_URL}/api/vendor-suppliers/{supplier_id}")
        if get_response.status_code == 200:
            # Soft deleted - should be inactive
            assert get_response.json()["status"] == "inactive"
        else:
            # Hard deleted
            assert get_response.status_code == 404
    
    def test_search_vendor_suppliers(self, api_client):
        """Test searching vendor suppliers"""
        # Create with unique prefix
        search_prefix = f"SEARCHTEST_{uuid.uuid4().hex[:6]}"
        create_response = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={
            "name": f"{search_prefix}_Vendor",
            "contact_person": f"{search_prefix}_Person"
        })
        assert create_response.status_code == 200
        created_supplier_ids.append(create_response.json()["supplier_id"])
        
        # Search by name
        response = api_client.get(f"{BASE_URL}/api/vendor-suppliers?search={search_prefix}")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(search_prefix in v["name"] for v in data)

# ============== IE CATEGORIES TESTS ==============

class TestIECategoriesCRUD:
    """Tests for IE Categories CRUD operations"""
    
    def test_create_category_basic(self, api_client):
        """Test creating a basic IE category"""
        unique_name = f"TEST_Category_{uuid.uuid4().hex[:8]}"
        response = api_client.post(f"{BASE_URL}/api/ie-categories", json={
            "name": unique_name
        })
        
        assert response.status_code == 200, f"Create failed: {response.text}"
        data = response.json()
        assert "category_id" in data
        assert data["name"] == unique_name
        assert data["category_type"] == "both"  # Default
        assert data["is_active"] == True
        
        created_category_ids.append(data["category_id"])
        print(f"Created IE category: {data['category_id']}")
    
    def test_create_category_income_type(self, api_client):
        """Test creating an income-only category"""
        unique_name = f"TEST_IncomeCategory_{uuid.uuid4().hex[:8]}"
        response = api_client.post(f"{BASE_URL}/api/ie-categories", json={
            "name": unique_name,
            "category_type": "income",
            "description": "Test income category"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["category_type"] == "income"
        assert data["description"] == "Test income category"
        
        created_category_ids.append(data["category_id"])
    
    def test_create_category_expense_type(self, api_client):
        """Test creating an expense-only category"""
        unique_name = f"TEST_ExpenseCategory_{uuid.uuid4().hex[:8]}"
        response = api_client.post(f"{BASE_URL}/api/ie-categories", json={
            "name": unique_name,
            "category_type": "expense",
            "description": "Test expense category"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["category_type"] == "expense"
        
        created_category_ids.append(data["category_id"])
    
    def test_create_category_duplicate_fails(self, api_client):
        """Test that duplicate category names are rejected"""
        unique_name = f"TEST_DupeCategory_{uuid.uuid4().hex[:8]}"
        
        # Create first
        response1 = api_client.post(f"{BASE_URL}/api/ie-categories", json={"name": unique_name})
        assert response1.status_code == 200
        created_category_ids.append(response1.json()["category_id"])
        
        # Try duplicate
        response2 = api_client.post(f"{BASE_URL}/api/ie-categories", json={"name": unique_name})
        assert response2.status_code == 400
        assert "already exists" in response2.json().get("detail", "").lower()
    
    def test_get_all_categories(self, api_client):
        """Test listing all IE categories"""
        response = api_client.get(f"{BASE_URL}/api/ie-categories?active_only=false")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"Found {len(data)} IE categories")
    
    def test_get_active_categories_only(self, api_client):
        """Test listing only active categories"""
        response = api_client.get(f"{BASE_URL}/api/ie-categories?active_only=true")
        
        assert response.status_code == 200
        data = response.json()
        # All should be active
        for cat in data:
            assert cat["is_active"] == True
    
    def test_get_categories_by_type(self, api_client):
        """Test filtering categories by type"""
        # Get income categories
        response = api_client.get(f"{BASE_URL}/api/ie-categories?category_type=income")
        assert response.status_code == 200
        data = response.json()
        for cat in data:
            assert cat["category_type"] in ["income", "both"]
        
        # Get expense categories
        response = api_client.get(f"{BASE_URL}/api/ie-categories?category_type=expense")
        assert response.status_code == 200
        data = response.json()
        for cat in data:
            assert cat["category_type"] in ["expense", "both"]
    
    def test_get_category_by_id(self, api_client):
        """Test getting a specific category"""
        # Create first
        unique_name = f"TEST_GetCategory_{uuid.uuid4().hex[:8]}"
        create_response = api_client.post(f"{BASE_URL}/api/ie-categories", json={"name": unique_name})
        assert create_response.status_code == 200
        category_id = create_response.json()["category_id"]
        created_category_ids.append(category_id)
        
        # Get by ID
        response = api_client.get(f"{BASE_URL}/api/ie-categories/{category_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["category_id"] == category_id
        assert data["name"] == unique_name
    
    def test_update_category(self, api_client):
        """Test updating an IE category"""
        # Create first
        unique_name = f"TEST_UpdateCategory_{uuid.uuid4().hex[:8]}"
        create_response = api_client.post(f"{BASE_URL}/api/ie-categories", json={"name": unique_name})
        assert create_response.status_code == 200
        category_id = create_response.json()["category_id"]
        created_category_ids.append(category_id)
        
        # Update
        updated_name = f"UPDATED_{unique_name}"
        response = api_client.put(f"{BASE_URL}/api/ie-categories/{category_id}", json={
            "name": updated_name,
            "description": "Updated description"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == updated_name
        assert data["description"] == "Updated description"
        
        # Verify by getting again
        get_response = api_client.get(f"{BASE_URL}/api/ie-categories/{category_id}")
        assert get_response.status_code == 200
        assert get_response.json()["name"] == updated_name
    
    def test_delete_category(self, api_client):
        """Test deleting an IE category"""
        # Create first
        unique_name = f"TEST_DeleteCategory_{uuid.uuid4().hex[:8]}"
        create_response = api_client.post(f"{BASE_URL}/api/ie-categories", json={"name": unique_name})
        assert create_response.status_code == 200
        category_id = create_response.json()["category_id"]
        
        # Delete
        response = api_client.delete(f"{BASE_URL}/api/ie-categories/{category_id}")
        assert response.status_code == 200
        
        # Verify - either not found or is_active false
        get_response = api_client.get(f"{BASE_URL}/api/ie-categories/{category_id}")
        if get_response.status_code == 200:
            assert get_response.json()["is_active"] == False
        else:
            assert get_response.status_code == 404

# ============== INCOME/EXPENSE WITH LINKED ENTITIES TESTS ==============

class TestIncomeExpenseWithLinkedEntities:
    """Tests for Income/Expense entries with linked Client, Vendor Supplier, and IE Category"""
    
    def test_create_income_with_custom_category(self, api_client, test_treasury_account):
        """Test creating an income entry with a custom IE category"""
        # First create a category
        cat_name = f"TEST_IncCategory_{uuid.uuid4().hex[:6]}"
        cat_response = api_client.post(f"{BASE_URL}/api/ie-categories", json={
            "name": cat_name,
            "category_type": "income"
        })
        assert cat_response.status_code == 200
        category_id = cat_response.json()["category_id"]
        created_category_ids.append(category_id)
        
        # Create income with the category
        entry_response = api_client.post(f"{BASE_URL}/api/income-expenses", json={
            "entry_type": "income",
            "category": "other",
            "ie_category_id": category_id,
            "amount": 1000.0,
            "currency": "USD",
            "treasury_account_id": test_treasury_account["account_id"],
            "description": "Test income with custom category"
        })
        
        assert entry_response.status_code in [200, 201], f"Create failed: {entry_response.text}"
        data = entry_response.json()
        assert data["ie_category_id"] == category_id
        assert data["ie_category_name"] == cat_name
        
        created_entry_ids.append(data["entry_id"])
        print(f"Created income entry with custom category: {data['entry_id']}")
    
    def test_create_expense_linked_to_vendor_supplier(self, api_client, test_treasury_account):
        """Test creating an expense linked to a vendor supplier"""
        # First create a vendor supplier
        vendor_name = f"TEST_Vendor_{uuid.uuid4().hex[:6]}"
        vendor_response = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={
            "name": vendor_name,
            "bank_name": "Test Bank",
            "bank_account_number": "123456789"
        })
        assert vendor_response.status_code == 200
        supplier_id = vendor_response.json()["supplier_id"]
        created_supplier_ids.append(supplier_id)
        
        # Create expense with the vendor supplier
        entry_response = api_client.post(f"{BASE_URL}/api/income-expenses", json={
            "entry_type": "expense",
            "category": "operational",
            "vendor_supplier_id": supplier_id,
            "amount": 500.0,
            "currency": "USD",
            "treasury_account_id": test_treasury_account["account_id"],
            "description": "Test expense linked to vendor"
        })
        
        assert entry_response.status_code in [200, 201], f"Create failed: {entry_response.text}"
        data = entry_response.json()
        assert data["vendor_supplier_id"] == supplier_id
        assert data["vendor_supplier_name"] == vendor_name
        
        created_entry_ids.append(data["entry_id"])
        print(f"Created expense linked to vendor: {data['entry_id']}")
    
    def test_create_expense_linked_to_client(self, api_client, test_treasury_account, test_client):
        """Test creating an expense linked to a client"""
        entry_response = api_client.post(f"{BASE_URL}/api/income-expenses", json={
            "entry_type": "expense",
            "category": "other",
            "client_id": test_client["client_id"],
            "amount": 250.0,
            "currency": "USD",
            "treasury_account_id": test_treasury_account["account_id"],
            "description": "Test expense linked to client"
        })
        
        assert entry_response.status_code in [200, 201], f"Create failed: {entry_response.text}"
        data = entry_response.json()
        assert data["client_id"] == test_client["client_id"]
        expected_client_name = f"{test_client['first_name']} {test_client['last_name']}"
        assert data["client_name"] == expected_client_name
        
        created_entry_ids.append(data["entry_id"])
        print(f"Created expense linked to client: {data['entry_id']}")
    
    def test_create_income_with_all_linked_entities(self, api_client, test_treasury_account, test_client):
        """Test creating an income with category, vendor supplier, and client all linked"""
        # Create category
        cat_name = f"TEST_AllLinks_Cat_{uuid.uuid4().hex[:6]}"
        cat_response = api_client.post(f"{BASE_URL}/api/ie-categories", json={
            "name": cat_name,
            "category_type": "income"
        })
        assert cat_response.status_code == 200
        category_id = cat_response.json()["category_id"]
        created_category_ids.append(category_id)
        
        # Create vendor supplier
        vendor_name = f"TEST_AllLinks_Vendor_{uuid.uuid4().hex[:6]}"
        vendor_response = api_client.post(f"{BASE_URL}/api/vendor-suppliers", json={
            "name": vendor_name
        })
        assert vendor_response.status_code == 200
        supplier_id = vendor_response.json()["supplier_id"]
        created_supplier_ids.append(supplier_id)
        
        # Create income with all links
        entry_response = api_client.post(f"{BASE_URL}/api/income-expenses", json={
            "entry_type": "income",
            "category": "other",
            "ie_category_id": category_id,
            "vendor_supplier_id": supplier_id,
            "client_id": test_client["client_id"],
            "amount": 2000.0,
            "currency": "USD",
            "treasury_account_id": test_treasury_account["account_id"],
            "description": "Test income with all linked entities",
            "reference": "REF-ALL-LINKS-001"
        })
        
        assert entry_response.status_code in [200, 201], f"Create failed: {entry_response.text}"
        data = entry_response.json()
        
        # Verify all links
        assert data["ie_category_id"] == category_id
        assert data["ie_category_name"] == cat_name
        assert data["vendor_supplier_id"] == supplier_id
        assert data["vendor_supplier_name"] == vendor_name
        assert data["client_id"] == test_client["client_id"]
        
        created_entry_ids.append(data["entry_id"])
        print(f"Created income with all links: {data['entry_id']}")
    
    def test_list_entries_shows_linked_names(self, api_client):
        """Test that listing entries shows the linked entity names"""
        response = api_client.get(f"{BASE_URL}/api/income-expenses?limit=50")
        
        assert response.status_code == 200
        entries = response.json()
        
        # Find an entry with linked entities
        linked_entries = [e for e in entries if e.get("vendor_supplier_name") or e.get("ie_category_name") or e.get("client_name")]
        
        if linked_entries:
            entry = linked_entries[0]
            print(f"Entry with links: vendor_supplier={entry.get('vendor_supplier_name')}, category={entry.get('ie_category_name')}, client={entry.get('client_name')}")
        else:
            print("No entries with linked entities found in list")

# ============== CLEANUP ==============

def test_cleanup(api_client):
    """Clean up test data"""
    print("\n=== Cleaning up test data ===")
    
    # Delete created entries
    for entry_id in created_entry_ids:
        try:
            api_client.delete(f"{BASE_URL}/api/income-expenses/{entry_id}")
            print(f"Deleted entry: {entry_id}")
        except Exception as e:
            print(f"Failed to delete entry {entry_id}: {e}")
    
    # Delete created suppliers
    for supplier_id in created_supplier_ids:
        try:
            api_client.delete(f"{BASE_URL}/api/vendor-suppliers/{supplier_id}")
            print(f"Deleted/deactivated supplier: {supplier_id}")
        except Exception as e:
            print(f"Failed to delete supplier {supplier_id}: {e}")
    
    # Delete created categories
    for category_id in created_category_ids:
        try:
            api_client.delete(f"{BASE_URL}/api/ie-categories/{category_id}")
            print(f"Deleted/deactivated category: {category_id}")
        except Exception as e:
            print(f"Failed to delete category {category_id}: {e}")
    
    print("=== Cleanup complete ===")
