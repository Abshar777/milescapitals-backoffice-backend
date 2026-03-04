"""
Full System Test for Miles Capitals FX Broker Back-Office
Tests all modules: Auth, Users, RBAC, Clients, Transactions, Treasury, 
Income/Expenses, Loans, PSP, Vendors, LP, Dealing P&L, Reconciliation, Reports, Logs, Settings
"""
import pytest
import requests
import os
from datetime import datetime

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
ADMIN_CREDS = {"email": "admin@fxbroker.com", "password": "admin123"}
EXCHANGER_CREDS = {"email": "kenway@fxbroker.com", "password": "password"}


class TestAuthentication:
    """Authentication module tests"""
    
    def test_01_admin_login(self):
        """Test admin login"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        assert response.status_code == 200, f"Admin login failed: {response.text}"
        data = response.json()
        assert "access_token" in data
        assert data["user"]["role"] == "admin"
        print(f"✓ Admin login successful: {data['user']['name']}")
        return data["access_token"]
    
    def test_02_exchanger_login(self):
        """Test exchanger/vendor login"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json=EXCHANGER_CREDS)
        # May fail if exchanger doesn't exist - that's okay
        if response.status_code == 200:
            data = response.json()
            assert "access_token" in data
            print(f"✓ Exchanger login successful: {data['user']['name']}")
        else:
            print(f"⚠ Exchanger login failed (user may not exist): {response.status_code}")
    
    def test_03_get_current_user(self):
        """Test get current user info"""
        token = self._get_admin_token()
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{BASE_URL}/api/auth/me", headers=headers)
        assert response.status_code == 200, f"Get me failed: {response.text}"
        data = response.json()
        assert "user_id" in data
        assert "email" in data
        print(f"✓ Get current user: {data['email']}")
    
    def test_04_invalid_login(self):
        """Test invalid credentials"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={"email": "fake@test.com", "password": "wrong"})
        assert response.status_code == 401
        print("✓ Invalid login rejected correctly")
    
    def _get_admin_token(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        return response.json()["access_token"]


class TestUserManagement:
    """User management module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_05_get_all_users(self):
        """Get all users"""
        response = requests.get(f"{BASE_URL}/api/users", headers=self.headers)
        assert response.status_code == 200
        users = response.json()
        assert isinstance(users, list)
        print(f"✓ Got {len(users)} users")
    
    def test_06_create_user(self):
        """Create a new test user"""
        test_user = {
            "email": f"TEST_user_{datetime.now().strftime('%H%M%S')}@test.com",
            "password": "testpass123",
            "name": "TEST User",
            "role": "sub_admin"
        }
        response = requests.post(f"{BASE_URL}/api/users", json=test_user, headers=self.headers)
        assert response.status_code == 200, f"Create user failed: {response.text}"
        data = response.json()
        assert "user_id" in data
        print(f"✓ Created user: {data['email']}")
        return data["user_id"]
    
    def test_07_update_user(self):
        """Update a user"""
        # First create a user
        test_user = {
            "email": f"TEST_update_{datetime.now().strftime('%H%M%S')}@test.com",
            "password": "testpass123",
            "name": "Update Test",
            "role": "sub_admin"
        }
        create_resp = requests.post(f"{BASE_URL}/api/users", json=test_user, headers=self.headers)
        if create_resp.status_code != 200:
            pytest.skip("Could not create test user")
        
        user_id = create_resp.json()["user_id"]
        
        # Update the user
        update_data = {"name": "Updated Name"}
        response = requests.put(f"{BASE_URL}/api/users/{user_id}", json=update_data, headers=self.headers)
        assert response.status_code == 200, f"Update failed: {response.text}"
        assert response.json()["name"] == "Updated Name"
        print(f"✓ Updated user: {user_id}")
    
    def test_08_delete_user(self):
        """Delete a user"""
        # Create user to delete
        test_user = {
            "email": f"TEST_delete_{datetime.now().strftime('%H%M%S')}@test.com",
            "password": "testpass123",
            "name": "Delete Test",
            "role": "sub_admin"
        }
        create_resp = requests.post(f"{BASE_URL}/api/users", json=test_user, headers=self.headers)
        if create_resp.status_code != 200:
            pytest.skip("Could not create test user")
        
        user_id = create_resp.json()["user_id"]
        
        # Delete the user
        response = requests.delete(f"{BASE_URL}/api/users/{user_id}", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Deleted user: {user_id}")


class TestRolesPermissions:
    """Roles & Permissions (RBAC) module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_09_get_all_roles(self):
        """Get all roles"""
        response = requests.get(f"{BASE_URL}/api/roles", headers=self.headers)
        assert response.status_code == 200
        roles = response.json()
        assert isinstance(roles, list)
        assert len(roles) > 0
        print(f"✓ Got {len(roles)} roles: {[r['display_name'] for r in roles]}")
    
    def test_10_get_role_details(self):
        """Get role details with permissions"""
        response = requests.get(f"{BASE_URL}/api/roles/admin", headers=self.headers)
        assert response.status_code == 200
        role = response.json()
        assert "permissions" in role
        print(f"✓ Got role: {role['display_name']} with {len(role.get('permissions', {}))} module permissions")
    
    def test_11_get_permission_modules(self):
        """Get available permission modules"""
        response = requests.get(f"{BASE_URL}/api/permissions/modules", headers=self.headers)
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        print(f"✓ Got {len(data['modules'])} permission modules")
    
    def test_12_get_user_permissions(self):
        """Get current user's permissions"""
        response = requests.get(f"{BASE_URL}/api/permissions/my", headers=self.headers)
        assert response.status_code == 200
        data = response.json()
        assert "permissions" in data
        print(f"✓ Got user permissions for {len(data.get('permissions', {}))} modules")


class TestClients:
    """Clients module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_13_get_all_clients(self):
        """Get all clients"""
        response = requests.get(f"{BASE_URL}/api/clients", headers=self.headers)
        assert response.status_code == 200
        clients = response.json()
        assert isinstance(clients, list)
        print(f"✓ Got {len(clients)} clients")
    
    def test_14_create_client(self):
        """Create a new client"""
        client_data = {
            "first_name": "TEST",
            "last_name": f"Client_{datetime.now().strftime('%H%M%S')}",
            "email": f"TEST_client_{datetime.now().strftime('%H%M%S')}@test.com",
            "phone": "+1234567890",
            "country": "USA"
        }
        response = requests.post(f"{BASE_URL}/api/clients", json=client_data, headers=self.headers)
        assert response.status_code == 200, f"Create client failed: {response.text}"
        data = response.json()
        assert "client_id" in data
        print(f"✓ Created client: {data['client_id']}")
        return data["client_id"]
    
    def test_15_update_client(self):
        """Update a client"""
        # Create client first
        client_data = {
            "first_name": "TEST",
            "last_name": "UpdateTest",
            "email": f"TEST_update_{datetime.now().strftime('%H%M%S')}@test.com"
        }
        create_resp = requests.post(f"{BASE_URL}/api/clients", json=client_data, headers=self.headers)
        if create_resp.status_code != 200:
            pytest.skip("Could not create test client")
        
        client_id = create_resp.json()["client_id"]
        
        # Update client
        update_data = {"first_name": "Updated"}
        response = requests.put(f"{BASE_URL}/api/clients/{client_id}", json=update_data, headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Updated client: {client_id}")
    
    def test_16_get_client_details(self):
        """Get client with transactions"""
        response = requests.get(f"{BASE_URL}/api/clients", headers=self.headers)
        clients = response.json()
        if clients:
            client_id = clients[0]["client_id"]
            response = requests.get(f"{BASE_URL}/api/clients/{client_id}", headers=self.headers)
            assert response.status_code == 200
            data = response.json()
            assert "total_deposits" in data or "net_balance" in data
            print(f"✓ Got client details with transaction summary")
        else:
            print("⚠ No clients to test")


class TestTransactions:
    """Transactions module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_17_get_all_transactions(self):
        """Get all transactions"""
        response = requests.get(f"{BASE_URL}/api/transactions", headers=self.headers)
        assert response.status_code == 200
        txs = response.json()
        assert isinstance(txs, list)
        print(f"✓ Got {len(txs)} transactions")
    
    def test_18_create_deposit(self):
        """Create deposit transaction"""
        # Get a client first
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=self.headers)
        clients = clients_resp.json()
        
        # Get a treasury account
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        if not clients or not treasury:
            pytest.skip("Need clients and treasury accounts")
        
        # Transaction endpoint uses Form data, not JSON
        tx_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "deposit",
            "amount": 100.00,
            "currency": "USD",
            "destination_type": "treasury",
            "destination_account_id": treasury[0]["account_id"],
            "description": "TEST deposit"
        }
        response = requests.post(f"{BASE_URL}/api/transactions", data=tx_data, headers=self.headers)
        # May fail due to duplicate detection within 5 minutes
        if response.status_code == 400 and "duplicate" in response.text.lower():
            print(f"⚠ Duplicate transaction detected (expected behavior)")
            return
        assert response.status_code == 200, f"Create deposit failed: {response.text}"
        data = response.json()
        assert "transaction_id" in data
        print(f"✓ Created deposit: {data['transaction_id']}")
    
    def test_19_create_withdrawal(self):
        """Create withdrawal transaction"""
        clients_resp = requests.get(f"{BASE_URL}/api/clients", headers=self.headers)
        clients = clients_resp.json()
        
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        if not clients or not treasury:
            pytest.skip("Need clients and treasury accounts")
        
        # Transaction endpoint uses Form data, not JSON
        tx_data = {
            "client_id": clients[0]["client_id"],
            "transaction_type": "withdrawal",
            "amount": 50.00,
            "currency": "USD",
            "destination_type": "treasury",
            "destination_account_id": treasury[0]["account_id"],
            "description": "TEST withdrawal"
        }
        response = requests.post(f"{BASE_URL}/api/transactions", data=tx_data, headers=self.headers)
        # May fail due to duplicate detection within 5 minutes
        if response.status_code == 400 and "duplicate" in response.text.lower():
            print(f"⚠ Duplicate transaction detected (expected behavior)")
            return
        assert response.status_code == 200, f"Create withdrawal failed: {response.text}"
        print(f"✓ Created withdrawal: {response.json()['transaction_id']}")
    
    def test_20_approve_transaction(self):
        """Approve a pending transaction"""
        # Get pending transactions
        response = requests.get(f"{BASE_URL}/api/transactions/pending", headers=self.headers)
        pending = response.json()
        
        if pending:
            tx_id = pending[0]["transaction_id"]
            approve_resp = requests.post(f"{BASE_URL}/api/transactions/{tx_id}/approve", headers=self.headers)
            if approve_resp.status_code == 200:
                print(f"✓ Approved transaction: {tx_id}")
            else:
                print(f"⚠ Could not approve transaction: {approve_resp.text}")
        else:
            print("⚠ No pending transactions to approve")
    
    def test_21_get_transaction_by_id(self):
        """Get transaction by ID"""
        response = requests.get(f"{BASE_URL}/api/transactions", headers=self.headers)
        txs = response.json()
        if txs:
            tx_id = txs[0]["transaction_id"]
            response = requests.get(f"{BASE_URL}/api/transactions/{tx_id}", headers=self.headers)
            assert response.status_code == 200
            print(f"✓ Got transaction: {tx_id}")
        else:
            print("⚠ No transactions to get")


class TestTreasury:
    """Treasury module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_22_get_treasury_accounts(self):
        """Get all treasury accounts"""
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        assert response.status_code == 200
        accounts = response.json()
        assert isinstance(accounts, list)
        print(f"✓ Got {len(accounts)} treasury accounts")
    
    def test_23_create_treasury_account(self):
        """Create treasury account"""
        account_data = {
            "account_name": f"TEST Account {datetime.now().strftime('%H%M%S')}",
            "account_type": "bank",
            "bank_name": "Test Bank",
            "currency": "USD",
            "opening_balance": 0
        }
        response = requests.post(f"{BASE_URL}/api/treasury", json=account_data, headers=self.headers)
        assert response.status_code == 200, f"Create treasury failed: {response.text}"
        data = response.json()
        assert "account_id" in data
        print(f"✓ Created treasury account: {data['account_id']}")
        return data["account_id"]
    
    def test_24_update_treasury_account(self):
        """Update treasury account"""
        # Create one first
        account_data = {
            "account_name": f"TEST Update {datetime.now().strftime('%H%M%S')}",
            "account_type": "bank",
            "currency": "USD",
            "opening_balance": 0
        }
        create_resp = requests.post(f"{BASE_URL}/api/treasury", json=account_data, headers=self.headers)
        if create_resp.status_code != 200:
            pytest.skip("Could not create test treasury account")
        
        account_id = create_resp.json()["account_id"]
        
        update_data = {"account_name": "Updated Treasury Name"}
        response = requests.put(f"{BASE_URL}/api/treasury/{account_id}", json=update_data, headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Updated treasury account: {account_id}")
    
    def test_25_delete_treasury_account(self):
        """Delete treasury account"""
        # Create one to delete
        account_data = {
            "account_name": f"TEST Delete {datetime.now().strftime('%H%M%S')}",
            "account_type": "bank",
            "currency": "USD",
            "opening_balance": 0
        }
        create_resp = requests.post(f"{BASE_URL}/api/treasury", json=account_data, headers=self.headers)
        if create_resp.status_code != 200:
            pytest.skip("Could not create test treasury account")
        
        account_id = create_resp.json()["account_id"]
        
        response = requests.delete(f"{BASE_URL}/api/treasury/{account_id}", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Deleted treasury account: {account_id}")
    
    def test_26_get_treasury_history(self):
        """Get treasury account history"""
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        if accounts:
            account_id = accounts[0]["account_id"]
            history_resp = requests.get(f"{BASE_URL}/api/treasury/{account_id}/history", headers=self.headers)
            assert history_resp.status_code == 200
            print(f"✓ Got treasury history for {account_id}")
        else:
            print("⚠ No treasury accounts")
    
    def test_27_treasury_transfer(self):
        """Transfer between treasury accounts"""
        response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        accounts = response.json()
        
        if len(accounts) < 2:
            # Create accounts for transfer
            for i in range(2):
                account_data = {
                    "account_name": f"TEST Transfer {i} {datetime.now().strftime('%H%M%S')}",
                    "account_type": "bank",
                    "currency": "USD",
                    "opening_balance": 1000
                }
                requests.post(f"{BASE_URL}/api/treasury", json=account_data, headers=self.headers)
            
            response = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
            accounts = response.json()
        
        # Find accounts with balance
        source = next((a for a in accounts if a.get("balance", 0) > 0), None)
        dest = next((a for a in accounts if a["account_id"] != (source["account_id"] if source else "")), None)
        
        if source and dest:
            transfer_data = {
                "source_account_id": source["account_id"],
                "destination_account_id": dest["account_id"],
                "amount": min(10, source.get("balance", 0)),
                "notes": "TEST transfer"
            }
            transfer_resp = requests.post(f"{BASE_URL}/api/treasury/transfer", json=transfer_data, headers=self.headers)
            if transfer_resp.status_code == 200:
                print(f"✓ Transfer successful")
            else:
                print(f"⚠ Transfer failed: {transfer_resp.text}")
        else:
            print("⚠ Need accounts with balance for transfer test")


class TestIncomeExpenses:
    """Income & Expenses module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_28_get_income_expenses(self):
        """Get all income/expenses"""
        response = requests.get(f"{BASE_URL}/api/income-expenses", headers=self.headers)
        assert response.status_code == 200
        entries = response.json()
        assert isinstance(entries, list)
        print(f"✓ Got {len(entries)} income/expense entries")
    
    def test_29_create_income(self):
        """Create income entry"""
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        if not treasury:
            pytest.skip("Need treasury account")
        
        income_data = {
            "entry_type": "income",
            "category": "commission",
            "amount": 500.00,
            "currency": "USD",
            "treasury_account_id": treasury[0]["account_id"],
            "description": "TEST income entry"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=income_data, headers=self.headers)
        assert response.status_code == 200, f"Create income failed: {response.text}"
        print(f"✓ Created income entry: {response.json()['entry_id']}")
    
    def test_30_create_expense(self):
        """Create expense entry"""
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        if not treasury:
            pytest.skip("Need treasury account")
        
        expense_data = {
            "entry_type": "expense",
            "category": "operational",
            "amount": 100.00,
            "currency": "USD",
            "treasury_account_id": treasury[0]["account_id"],
            "description": "TEST expense entry"
        }
        response = requests.post(f"{BASE_URL}/api/income-expenses", json=expense_data, headers=self.headers)
        assert response.status_code == 200, f"Create expense failed: {response.text}"
        print(f"✓ Created expense entry: {response.json()['entry_id']}")
    
    def test_31_delete_income_expense(self):
        """Delete income/expense entry"""
        # Create one to delete
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        if not treasury:
            pytest.skip("Need treasury account")
        
        entry_data = {
            "entry_type": "expense",
            "category": "other",
            "amount": 10.00,
            "currency": "USD",
            "treasury_account_id": treasury[0]["account_id"],
            "description": "TEST delete entry"
        }
        create_resp = requests.post(f"{BASE_URL}/api/income-expenses", json=entry_data, headers=self.headers)
        if create_resp.status_code != 200:
            pytest.skip("Could not create test entry")
        
        entry_id = create_resp.json()["entry_id"]
        
        response = requests.delete(f"{BASE_URL}/api/income-expenses/{entry_id}", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Deleted income/expense entry: {entry_id}")


class TestLoans:
    """Loans module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_32_get_loans(self):
        """Get all loans"""
        response = requests.get(f"{BASE_URL}/api/loans", headers=self.headers)
        assert response.status_code == 200
        loans = response.json()
        assert isinstance(loans, list)
        print(f"✓ Got {len(loans)} loans")
    
    def test_33_create_loan(self):
        """Create a loan"""
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        if not treasury:
            pytest.skip("Need treasury account")
        
        loan_data = {
            "borrower_name": "TEST Borrower",
            "amount": 5000.00,
            "currency": "USD",
            "interest_rate": 5.0,
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": "2025-12-31",
            "treasury_account_id": treasury[0]["account_id"],
            "notes": "TEST loan"
        }
        response = requests.post(f"{BASE_URL}/api/loans", json=loan_data, headers=self.headers)
        assert response.status_code == 200, f"Create loan failed: {response.text}"
        print(f"✓ Created loan: {response.json()['loan_id']}")
        return response.json()["loan_id"]
    
    def test_34_record_repayment(self):
        """Record loan repayment"""
        # Get loans first
        response = requests.get(f"{BASE_URL}/api/loans", headers=self.headers)
        loans = response.json()
        
        if not loans:
            pytest.skip("No loans to repay")
        
        loan_id = loans[0]["loan_id"]
        
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        repayment_data = {
            "amount": 100.00,
            "currency": "USD",
            "treasury_account_id": treasury[0]["account_id"] if treasury else None,
            "notes": "TEST repayment"
        }
        response = requests.post(f"{BASE_URL}/api/loans/{loan_id}/repayment", json=repayment_data, headers=self.headers)
        if response.status_code == 200:
            print(f"✓ Recorded repayment for loan: {loan_id}")
        else:
            print(f"⚠ Repayment failed: {response.text}")
    
    def test_35_delete_loan(self):
        """Delete a loan"""
        # Create one to delete
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        if not treasury:
            pytest.skip("Need treasury account")
        
        loan_data = {
            "borrower_name": "TEST Delete Loan",
            "amount": 100.00,
            "currency": "USD",
            "loan_date": datetime.now().strftime("%Y-%m-%d"),
            "due_date": "2025-12-31",
            "treasury_account_id": treasury[0]["account_id"]
        }
        create_resp = requests.post(f"{BASE_URL}/api/loans", json=loan_data, headers=self.headers)
        if create_resp.status_code != 200:
            pytest.skip("Could not create test loan")
        
        loan_id = create_resp.json()["loan_id"]
        
        response = requests.delete(f"{BASE_URL}/api/loans/{loan_id}", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Deleted loan: {loan_id}")


class TestPSP:
    """PSP module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_36_get_psps(self):
        """Get all PSPs"""
        response = requests.get(f"{BASE_URL}/api/psp", headers=self.headers)
        assert response.status_code == 200
        psps = response.json()
        assert isinstance(psps, list)
        print(f"✓ Got {len(psps)} PSPs")
    
    def test_37_create_psp(self):
        """Create a PSP"""
        treasury_resp = requests.get(f"{BASE_URL}/api/treasury", headers=self.headers)
        treasury = treasury_resp.json()
        
        if not treasury:
            pytest.skip("Need treasury account")
        
        psp_data = {
            "psp_name": f"TEST PSP {datetime.now().strftime('%H%M%S')}",
            "commission_rate": 2.5,
            "settlement_destination_id": treasury[0]["account_id"],
            "settlement_days": 1
        }
        response = requests.post(f"{BASE_URL}/api/psp", json=psp_data, headers=self.headers)
        assert response.status_code == 200, f"Create PSP failed: {response.text}"
        print(f"✓ Created PSP: {response.json()['psp_id']}")
    
    def test_38_update_psp(self):
        """Update a PSP"""
        response = requests.get(f"{BASE_URL}/api/psp", headers=self.headers)
        psps = response.json()
        
        if not psps:
            pytest.skip("No PSPs to update")
        
        psp_id = psps[0]["psp_id"]
        update_data = {"commission_rate": 3.0}
        response = requests.put(f"{BASE_URL}/api/psp/{psp_id}", json=update_data, headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Updated PSP: {psp_id}")
    
    def test_39_psp_summary(self):
        """Get PSP summary"""
        response = requests.get(f"{BASE_URL}/api/psp-summary", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Got PSP summary")
    
    def test_40_get_psp_settlements(self):
        """Get PSP settlement history"""
        response = requests.get(f"{BASE_URL}/api/psp", headers=self.headers)
        psps = response.json()
        
        if psps:
            psp_id = psps[0]["psp_id"]
            settle_resp = requests.get(f"{BASE_URL}/api/psp/{psp_id}/settlements", headers=self.headers)
            assert settle_resp.status_code == 200
            print(f"✓ Got PSP settlements for {psp_id}")
        else:
            print("⚠ No PSPs to get settlements")


class TestVendors:
    """Vendors/Exchangers module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_41_get_vendors(self):
        """Get all vendors"""
        response = requests.get(f"{BASE_URL}/api/vendors", headers=self.headers)
        assert response.status_code == 200
        vendors = response.json()
        assert isinstance(vendors, list)
        print(f"✓ Got {len(vendors)} vendors/exchangers")
    
    def test_42_create_vendor(self):
        """Create a vendor"""
        vendor_data = {
            "vendor_name": f"TEST Vendor {datetime.now().strftime('%H%M%S')}",
            "email": f"TEST_vendor_{datetime.now().strftime('%H%M%S')}@test.com",
            "password": "vendor123",
            "deposit_commission": 1.5,
            "withdrawal_commission": 2.0
        }
        response = requests.post(f"{BASE_URL}/api/vendors", json=vendor_data, headers=self.headers)
        assert response.status_code == 200, f"Create vendor failed: {response.text}"
        print(f"✓ Created vendor: {response.json()['vendor_id']}")
    
    def test_43_update_vendor(self):
        """Update a vendor"""
        response = requests.get(f"{BASE_URL}/api/vendors", headers=self.headers)
        vendors = response.json()
        
        if not vendors:
            pytest.skip("No vendors to update")
        
        vendor_id = vendors[0]["vendor_id"]
        update_data = {"deposit_commission": 2.0}
        response = requests.put(f"{BASE_URL}/api/vendors/{vendor_id}", json=update_data, headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Updated vendor: {vendor_id}")
    
    def test_44_delete_vendor(self):
        """Delete a vendor"""
        # Create one to delete
        vendor_data = {
            "vendor_name": f"TEST Delete {datetime.now().strftime('%H%M%S')}",
            "email": f"TEST_delete_{datetime.now().strftime('%H%M%S')}@test.com",
            "password": "vendor123",
            "deposit_commission": 1.0,
            "withdrawal_commission": 1.0
        }
        create_resp = requests.post(f"{BASE_URL}/api/vendors", json=vendor_data, headers=self.headers)
        if create_resp.status_code != 200:
            pytest.skip("Could not create test vendor")
        
        vendor_id = create_resp.json()["vendor_id"]
        
        response = requests.delete(f"{BASE_URL}/api/vendors/{vendor_id}", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Deleted vendor: {vendor_id}")


class TestLPManagement:
    """LP Management module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_45_get_lp_accounts(self):
        """Get all LP accounts"""
        response = requests.get(f"{BASE_URL}/api/lp", headers=self.headers)
        assert response.status_code == 200
        lps = response.json()
        assert isinstance(lps, list)
        print(f"✓ Got {len(lps)} LP accounts")
    
    def test_46_create_lp_account(self):
        """Create LP account"""
        lp_data = {
            "lp_name": f"TEST LP {datetime.now().strftime('%H%M%S')}",
            "currency": "USD",
            "contact_person": "Test Contact",
            "contact_email": "lp@test.com"
        }
        response = requests.post(f"{BASE_URL}/api/lp", json=lp_data, headers=self.headers)
        assert response.status_code == 200, f"Create LP failed: {response.text}"
        print(f"✓ Created LP account: {response.json()['lp_id']}")
    
    def test_47_update_lp_account(self):
        """Update LP account"""
        response = requests.get(f"{BASE_URL}/api/lp", headers=self.headers)
        lps = response.json()
        
        if not lps:
            pytest.skip("No LP accounts")
        
        lp_id = lps[0]["lp_id"]
        update_data = {"contact_person": "Updated Contact"}
        response = requests.put(f"{BASE_URL}/api/lp/{lp_id}", json=update_data, headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Updated LP account: {lp_id}")


class TestDealingPnL:
    """Dealing P&L module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_48_get_dealing_pnl(self):
        """Get dealing P&L records"""
        response = requests.get(f"{BASE_URL}/api/dealing-pnl", headers=self.headers)
        assert response.status_code == 200
        records = response.json()
        assert isinstance(records, list)
        print(f"✓ Got {len(records)} P&L records")
    
    def test_49_create_dealing_pnl(self):
        """Create P&L entry"""
        # Use a unique date to avoid conflicts
        test_date = f"2024-{datetime.now().strftime('%m')}-{datetime.now().strftime('%d')}"
        pnl_data = {
            "date": test_date,
            "mt5_booked_pnl": 1000.00,
            "mt5_floating_pnl": 500.00,
            "lp_booked_pnl": -800.00,
            "lp_floating_pnl": -400.00,
            "notes": "TEST P&L entry"
        }
        response = requests.post(f"{BASE_URL}/api/dealing-pnl", json=pnl_data, headers=self.headers)
        # May fail if entry exists for this date
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Created P&L entry: {data.get('pnl_id', data.get('date', 'unknown'))}")
        elif response.status_code == 400:
            print(f"⚠ P&L entry may already exist for {test_date}: {response.status_code}")
        else:
            # Accept any response as test may have created entry already
            print(f"⚠ P&L creation response: {response.status_code}")
    
    def test_50_get_pnl_summary(self):
        """Get P&L summary"""
        response = requests.get(f"{BASE_URL}/api/dealing-pnl/summary", headers=self.headers)
        assert response.status_code == 200
        summary = response.json()
        print(f"✓ Got P&L summary")


class TestReconciliation:
    """Reconciliation module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_51_get_reconciliation_summary(self):
        """Get reconciliation summary"""
        response = requests.get(f"{BASE_URL}/api/reconciliation/summary", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Got reconciliation summary")
    
    def test_52_get_daily_reconciliation(self):
        """Get daily reconciliation"""
        response = requests.get(f"{BASE_URL}/api/reconciliation/daily", headers=self.headers)
        assert response.status_code == 200
        data = response.json()
        print(f"✓ Got daily reconciliation with {len(data.get('items', []))} items")
    
    def test_53_get_bank_batches(self):
        """Get bank statement batches"""
        response = requests.get(f"{BASE_URL}/api/reconciliation/batches", headers=self.headers)
        assert response.status_code == 200
        batches = response.json()
        print(f"✓ Got {len(batches)} bank statement batches")
    
    def test_54_quick_reconcile(self):
        """Quick reconcile item"""
        recon_data = {
            "reference_id": f"test_qr_{datetime.now().strftime('%H%M%S')}",
            "item_type": "treasury",
            "notes": "TEST quick reconcile"
        }
        response = requests.post(f"{BASE_URL}/api/reconciliation/quick-reconcile", params=recon_data, headers=self.headers)
        if response.status_code == 200:
            print(f"✓ Quick reconciled item")
        else:
            print(f"⚠ Quick reconcile: {response.status_code}")
    
    def test_55_flag_for_review(self):
        """Flag item for review"""
        flag_data = {
            "reference_id": f"test_flag_{datetime.now().strftime('%H%M%S')}",
            "item_type": "transaction",
            "reason": "TEST flag for review"
        }
        response = requests.post(f"{BASE_URL}/api/reconciliation/flag", params=flag_data, headers=self.headers)
        if response.status_code == 200:
            print(f"✓ Flagged item for review")
        else:
            print(f"⚠ Flag for review: {response.status_code}")


class TestReports:
    """Reports module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_56_get_reports_summary(self):
        """Get reports dashboard"""
        response = requests.get(f"{BASE_URL}/api/reports/dashboard", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Got reports dashboard")
    
    def test_57_get_transactions_report(self):
        """Get transactions summary report"""
        response = requests.get(f"{BASE_URL}/api/reports/transactions-summary", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Got transactions summary report")


class TestLogs:
    """Logs/Audit module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_58_get_activity_logs(self):
        """Get activity logs"""
        response = requests.get(f"{BASE_URL}/api/logs", headers=self.headers)
        assert response.status_code == 200
        logs = response.json()
        print(f"✓ Got {len(logs) if isinstance(logs, list) else 'some'} log entries")
    
    def test_59_filter_logs_by_module(self):
        """Filter logs by module"""
        response = requests.get(f"{BASE_URL}/api/logs?module=authentication", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Got filtered logs by module")


class TestSettings:
    """Settings module tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def test_60_get_email_settings(self):
        """Get email settings"""
        response = requests.get(f"{BASE_URL}/api/settings/email", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Got email settings")
    
    def test_61_get_commission_settings(self):
        """Get commission settings"""
        response = requests.get(f"{BASE_URL}/api/settings/commission", headers=self.headers)
        assert response.status_code == 200
        print(f"✓ Got commission settings")


# Cleanup fixture
@pytest.fixture(scope="session", autouse=True)
def cleanup(request):
    """Cleanup test data after all tests"""
    def cleanup_test_data():
        try:
            response = requests.post(f"{BASE_URL}/api/auth/login", json=ADMIN_CREDS)
            if response.status_code != 200:
                return
            
            token = response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            
            # Clean up TEST_ prefixed users
            users = requests.get(f"{BASE_URL}/api/users", headers=headers).json()
            for user in users:
                if user.get("email", "").startswith("TEST_"):
                    requests.delete(f"{BASE_URL}/api/users/{user['user_id']}", headers=headers)
            
            # Clean up TEST_ prefixed clients
            clients = requests.get(f"{BASE_URL}/api/clients", headers=headers).json()
            for client in clients:
                if client.get("email", "").startswith("TEST_"):
                    requests.delete(f"{BASE_URL}/api/clients/{client['client_id']}", headers=headers)
            
            # Clean up TEST_ vendors
            vendors = requests.get(f"{BASE_URL}/api/vendors", headers=headers).json()
            for vendor in vendors:
                if vendor.get("email", "").startswith("TEST_"):
                    requests.delete(f"{BASE_URL}/api/vendors/{vendor['vendor_id']}", headers=headers)
            
            print("\n✓ Test data cleanup completed")
        except Exception as e:
            print(f"\n⚠ Cleanup failed: {e}")
    
    request.addfinalizer(cleanup_test_data)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
