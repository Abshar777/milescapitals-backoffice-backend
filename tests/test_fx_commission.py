"""
Tests for FX Rates and Commission Settings Endpoints
- GET /api/fx-rates - Live currency exchange rates
- POST /api/fx-rates/refresh - Force refresh rates (admin only)
- GET /api/fx-rates/convert - Currency conversion
- GET /api/settings/commission - Commission settings
- PUT /api/settings/commission - Update commission settings
- POST /api/transactions - Broker commission on transactions
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL').rstrip('/')

class TestFxRatesCommission:
    """Tests for FX rates and commission features"""
    
    @pytest.fixture(scope="class")
    def auth_token(self):
        """Get admin authentication token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "admin@fxbroker.com",
            "password": "password"
        })
        assert response.status_code == 200, f"Login failed: {response.text}"
        return response.json()["access_token"]
    
    @pytest.fixture(scope="class")
    def auth_headers(self, auth_token):
        """Get headers with auth token"""
        return {"Authorization": f"Bearer {auth_token}"}
    
    # ===== FX RATES TESTS =====
    
    def test_get_fx_rates(self, auth_headers):
        """GET /api/fx-rates - Returns live exchange rates with source indicator"""
        response = requests.get(f"{BASE_URL}/api/fx-rates", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        # Check response structure
        assert "rates" in data
        assert "source" in data
        assert "fetched_at" in data
        assert "cache_ttl_minutes" in data
        
        # Verify popular currencies are included
        popular_currencies = ["USD", "EUR", "GBP", "AED", "INR", "SAR", "JPY"]
        for curr in popular_currencies:
            assert curr in data["rates"], f"Missing popular currency: {curr}"
        
        # Verify source is 'live'
        assert data["source"] == "live", "FX rates should be from live API"
        
        # Verify USD rate is 1.0 (base currency)
        assert data["rates"]["USD"] == 1.0
        
        print(f"FX rates source: {data['source']}, fetched_at: {data['fetched_at']}")
        print(f"Sample rates: EUR={data['rates'].get('EUR')}, AED={data['rates'].get('AED')}")
    
    def test_fx_rates_refresh(self, auth_headers):
        """POST /api/fx-rates/refresh - Force refresh rates (admin only)"""
        response = requests.post(f"{BASE_URL}/api/fx-rates/refresh", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert data["message"] == "Rates refreshed"
        assert "source" in data
        assert "sample_rates" in data
        
        print(f"Refresh result: {data['message']}, source: {data['source']}")
    
    def test_fx_rates_convert_aed_to_usd(self, auth_headers):
        """GET /api/fx-rates/convert - Convert AED to USD"""
        response = requests.get(
            f"{BASE_URL}/api/fx-rates/convert",
            params={"amount": 1000, "from_currency": "AED", "to_currency": "USD"},
            headers=auth_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["from_currency"] == "AED"
        assert data["to_currency"] == "USD"
        assert data["amount"] == 1000.0
        assert "converted_amount" in data
        assert "usd_equivalent" in data
        assert "rate" in data
        
        # AED to USD rate should be around 0.27
        assert 0.20 < data["converted_amount"] / 1000 < 0.35, "AED/USD rate out of expected range"
        
        print(f"Conversion: 1000 AED = {data['converted_amount']} USD (rate: {data['rate']})")
    
    def test_fx_rates_convert_eur_to_inr(self, auth_headers):
        """GET /api/fx-rates/convert - Convert EUR to INR"""
        response = requests.get(
            f"{BASE_URL}/api/fx-rates/convert",
            params={"amount": 100, "from_currency": "EUR", "to_currency": "INR"},
            headers=auth_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["from_currency"] == "EUR"
        assert data["to_currency"] == "INR"
        # EUR > USD, USD > INR, so 100 EUR should be > 10000 INR
        assert data["converted_amount"] > 5000, "100 EUR should convert to > 5000 INR"
        
        print(f"Conversion: 100 EUR = {data['converted_amount']} INR")
    
    def test_fx_rates_convert_invalid_currency(self, auth_headers):
        """GET /api/fx-rates/convert - Invalid currency returns error"""
        response = requests.get(
            f"{BASE_URL}/api/fx-rates/convert",
            params={"amount": 100, "from_currency": "XXX", "to_currency": "USD"},
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "Unsupported currency" in response.json().get("detail", "")
    
    # ===== COMMISSION SETTINGS TESTS =====
    
    def test_get_commission_settings(self, auth_headers):
        """GET /api/settings/commission - Returns commission settings"""
        response = requests.get(f"{BASE_URL}/api/settings/commission", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "deposit_commission_rate" in data
        assert "withdrawal_commission_rate" in data
        assert "commission_enabled" in data
        
        print(f"Commission settings: deposit={data['deposit_commission_rate']}%, withdrawal={data['withdrawal_commission_rate']}%, enabled={data['commission_enabled']}")
    
    def test_update_commission_settings(self, auth_headers):
        """PUT /api/settings/commission - Update commission settings"""
        new_settings = {
            "deposit_commission_rate": 1.5,
            "withdrawal_commission_rate": 2.0,
            "commission_enabled": True
        }
        
        response = requests.put(
            f"{BASE_URL}/api/settings/commission",
            headers={**auth_headers, "Content-Type": "application/json"},
            json=new_settings
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["deposit_commission_rate"] == 1.5
        assert data["withdrawal_commission_rate"] == 2.0
        assert data["commission_enabled"] == True
        
        # Verify settings were persisted
        verify_response = requests.get(f"{BASE_URL}/api/settings/commission", headers=auth_headers)
        verify_data = verify_response.json()
        assert verify_data["deposit_commission_rate"] == 1.5
        assert verify_data["withdrawal_commission_rate"] == 2.0
        
        print(f"Commission settings updated and verified")
    
    # ===== TRANSACTION WITH BROKER COMMISSION TESTS =====
    
    def test_deposit_has_broker_commission(self, auth_headers):
        """POST /api/transactions - Deposit includes broker commission"""
        import time
        # First get a client and treasury account
        clients_response = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        assert clients_response.status_code == 200
        clients = clients_response.json()
        assert len(clients) > 0, "No clients found"
        client_id = clients[0]["client_id"]
        
        treasury_response = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers)
        assert treasury_response.status_code == 200
        treasuries = treasury_response.json()
        assert len(treasuries) > 0, "No treasury accounts found"
        treasury_id = treasuries[0]["account_id"]
        
        # Use unique amount based on timestamp to avoid duplicate detection
        unique_amount = 7000 + int(time.time() % 1000)
        
        # Create deposit transaction using multipart form
        response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers=auth_headers,
            data={
                "client_id": client_id,
                "transaction_type": "deposit",
                "amount": str(unique_amount),
                "currency": "USD",
                "base_currency": "USD",
                "destination_type": "treasury",
                "destination_account_id": treasury_id,
                "reference": f"TEST_BROKER_COMMISSION_DEPOSIT_{os.urandom(4).hex()}"
            }
        )
        assert response.status_code == 200, f"Transaction failed: {response.text}"
        
        data = response.json()
        # Verify broker commission fields
        assert "broker_commission_rate" in data
        assert "broker_commission_amount" in data
        assert "broker_commission_base_amount" in data
        assert "broker_commission_base_currency" in data
        
        # Commission should be 1.5% of amount
        assert data["broker_commission_rate"] == 1.5
        expected_commission = round(unique_amount * 0.015, 2)
        assert data["broker_commission_amount"] == expected_commission
        
        print(f"Deposit created with broker commission: rate={data['broker_commission_rate']}%, amount=${data['broker_commission_amount']}")
    
    def test_withdrawal_has_broker_commission(self, auth_headers):
        """POST /api/transactions - Withdrawal includes broker commission"""
        import time
        clients_response = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        clients = clients_response.json()
        client_id = clients[0]["client_id"]
        
        # Use unique amount based on timestamp to avoid duplicate detection
        unique_amount = 3000 + int(time.time() % 1000)
        
        # Create withdrawal transaction
        response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers=auth_headers,
            data={
                "client_id": client_id,
                "transaction_type": "withdrawal",
                "amount": str(unique_amount),
                "currency": "USD",
                "base_currency": "USD",
                "destination_type": "bank",
                "client_bank_name": "TEST_BANK",
                "client_bank_account_name": "Test Account",
                "client_bank_account_number": f"123456789{int(time.time())}",
                "client_bank_currency": "USD",
                "reference": f"TEST_BROKER_COMMISSION_WITHDRAWAL_{os.urandom(4).hex()}"
            }
        )
        assert response.status_code == 200, f"Transaction failed: {response.text}"
        
        data = response.json()
        # Withdrawal commission should be 2.0% of amount
        assert data["broker_commission_rate"] == 2.0
        expected_commission = round(unique_amount * 0.02, 2)
        assert data["broker_commission_amount"] == expected_commission
        
        print(f"Withdrawal created with broker commission: rate={data['broker_commission_rate']}%, amount=${data['broker_commission_amount']}")
    
    def test_transaction_with_base_currency(self, auth_headers):
        """POST /api/transactions - Commission calculated on base currency amount"""
        import time
        clients_response = requests.get(f"{BASE_URL}/api/clients", headers=auth_headers)
        clients = clients_response.json()
        client_id = clients[0]["client_id"]
        
        treasury_response = requests.get(f"{BASE_URL}/api/treasury", headers=auth_headers)
        treasuries = treasury_response.json()
        treasury_id = treasuries[0]["account_id"]
        
        # Use unique amounts based on timestamp
        unique_base_amount = 5000 + int(time.time() % 1000)
        unique_usd_amount = round(unique_base_amount * 0.27229, 2)  # Approximate AED to USD
        
        # Create deposit with AED as base currency
        response = requests.post(
            f"{BASE_URL}/api/transactions",
            headers=auth_headers,
            data={
                "client_id": client_id,
                "transaction_type": "deposit",
                "amount": str(unique_usd_amount),
                "currency": "USD",
                "base_currency": "AED",
                "base_amount": str(unique_base_amount),
                "destination_type": "treasury",
                "destination_account_id": treasury_id,
                "reference": f"TEST_BROKER_COMMISSION_AED_{os.urandom(4).hex()}"
            }
        )
        assert response.status_code == 200, f"Transaction failed: {response.text}"
        
        data = response.json()
        assert data["broker_commission_base_currency"] == "AED"
        assert data["broker_commission_rate"] == 1.5
        # Base amount commission = 1.5% of base_amount AED
        expected_commission_base = round(unique_base_amount * 0.015, 2)
        # Allow small rounding tolerance
        assert abs(data["broker_commission_base_amount"] - expected_commission_base) <= 0.02
        
        print(f"Transaction with AED base currency: commission_base={data['broker_commission_base_amount']} {data['broker_commission_base_currency']}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
