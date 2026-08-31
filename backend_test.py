#!/usr/bin/env python3
"""
Backend API Test Suite for Factory Order Management - Auth + OTP + Permissions
Tests admin/user authentication, OTP flow, and permission management.
"""

import requests
import json
import re
import sys
from typing import Optional, Dict, Any

# Base URL from frontend/.env
BASE_URL = "https://dev-clone-7.preview.emergentagent.com/api"

# Test credentials (seeded users)
# Can use either email or username for login
ADMIN_EMAIL = "admin@factory.com"  # or "admin"
ADMIN_PASSWORD = "admin123"
USER_EMAIL = "user@factory.com"  # or "user"
USER_PASSWORD = "user123"

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def add_pass(self, test_name: str, details: str = ""):
        self.passed += 1
        self.tests.append({"name": test_name, "status": "PASS", "details": details})
        print(f"{GREEN}✓ PASS{RESET}: {test_name}")
        if details:
            print(f"  {details}")
    
    def add_fail(self, test_name: str, details: str = ""):
        self.failed += 1
        self.tests.append({"name": test_name, "status": "FAIL", "details": details})
        print(f"{RED}✗ FAIL{RESET}: {test_name}")
        if details:
            print(f"  {details}")
    
    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*70}")
        print(f"TEST SUMMARY: {self.passed}/{total} passed")
        if self.failed > 0:
            print(f"{RED}Failed tests:{RESET}")
            for t in self.tests:
                if t["status"] == "FAIL":
                    print(f"  - {t['name']}")
        print(f"{'='*70}\n")
        return self.failed == 0

def read_otp_from_logs(challenge_id: str, email: str) -> Optional[str]:
    """Read OTP code from backend logs."""
    log_files = [
        "/var/log/supervisor/backend.out.log",
        "/var/log/supervisor/backend.err.log"
    ]
    
    pattern = rf"Admin OTP for {re.escape(email)} \(challenge {re.escape(challenge_id)}\): (\d{{6}})"
    
    for log_file in log_files:
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                match = re.search(pattern, content)
                if match:
                    return match.group(1)
        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"{YELLOW}Warning: Error reading {log_file}: {e}{RESET}")
    
    return None

def test_admin_login_otp_step1(result: TestResult) -> Optional[Dict[str, Any]]:
    """Test 1: Admin login should return OTP challenge (no token)."""
    print(f"\n{BLUE}Test 1: Admin login - OTP required{RESET}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 1: Admin login OTP step 1", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return None
        
        data = response.json()
        
        # Verify response structure
        if not data.get("otp_required"):
            result.add_fail("Test 1: Admin login OTP step 1", 
                          f"Expected otp_required=true, got: {data}")
            return None
        
        if not data.get("challenge_id"):
            result.add_fail("Test 1: Admin login OTP step 1", 
                          "Missing challenge_id in response")
            return None
        
        if "token" in data:
            result.add_fail("Test 1: Admin login OTP step 1", 
                          "Token should NOT be present in OTP challenge response")
            return None
        
        result.add_pass("Test 1: Admin login OTP step 1", 
                       f"challenge_id={data['challenge_id']}, sent_to={data.get('sent_to')}, email_sent={data.get('email_sent')}")
        return data
        
    except Exception as e:
        result.add_fail("Test 1: Admin login OTP step 1", f"Exception: {str(e)}")
        return None

def test_admin_verify_otp(result: TestResult, challenge_data: Dict[str, Any]) -> Optional[str]:
    """Test 2: Verify OTP and get admin token."""
    print(f"\n{BLUE}Test 2: Admin OTP verification{RESET}")
    
    challenge_id = challenge_data.get("challenge_id")
    if not challenge_id:
        result.add_fail("Test 2: Admin OTP verification", "No challenge_id from previous test")
        return None
    
    # Read OTP from logs
    otp_code = read_otp_from_logs(challenge_id, "admin@factory.com")
    if not otp_code:
        result.add_fail("Test 2: Admin OTP verification", 
                       f"Could not find OTP in logs for challenge {challenge_id}")
        return None
    
    print(f"  Found OTP code: {otp_code}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/auth/verify-otp",
            json={"challenge_id": challenge_id, "code": otp_code},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 2: Admin OTP verification", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return None
        
        data = response.json()
        
        if not data.get("token"):
            result.add_fail("Test 2: Admin OTP verification", "Missing token in response")
            return None
        
        if not data.get("user"):
            result.add_fail("Test 2: Admin OTP verification", "Missing user in response")
            return None
        
        if data["user"].get("role") != "admin":
            result.add_fail("Test 2: Admin OTP verification", 
                          f"Expected role=admin, got {data['user'].get('role')}")
            return None
        
        result.add_pass("Test 2: Admin OTP verification", 
                       f"Token received, user.role={data['user']['role']}")
        return data["token"]
        
    except Exception as e:
        result.add_fail("Test 2: Admin OTP verification", f"Exception: {str(e)}")
        return None

def test_admin_me(result: TestResult, token: str):
    """Test 2b: Verify /auth/me with admin token."""
    print(f"\n{BLUE}Test 2b: GET /auth/me with admin token{RESET}")
    
    try:
        response = requests.get(
            f"{BASE_URL}/auth/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 2b: GET /auth/me", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return
        
        data = response.json()
        
        if data.get("role") != "admin":
            result.add_fail("Test 2b: GET /auth/me", 
                          f"Expected role=admin, got {data.get('role')}")
            return
        
        result.add_pass("Test 2b: GET /auth/me", 
                       f"Admin user verified: {data.get('email')}")
        
    except Exception as e:
        result.add_fail("Test 2b: GET /auth/me", f"Exception: {str(e)}")

def test_wrong_otp(result: TestResult):
    """Test 3: Wrong OTP should return 401."""
    print(f"\n{BLUE}Test 3: Wrong OTP code{RESET}")
    
    # Get a fresh challenge
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 3: Wrong OTP", f"Login failed: {response.status_code}")
            return
        
        data = response.json()
        challenge_id = data.get("challenge_id")
        
        if not challenge_id:
            result.add_fail("Test 3: Wrong OTP", "No challenge_id received")
            return
        
        # Try with wrong code
        response = requests.post(
            f"{BASE_URL}/auth/verify-otp",
            json={"challenge_id": challenge_id, "code": "000000"},
            timeout=10
        )
        
        if response.status_code != 401:
            result.add_fail("Test 3: Wrong OTP", 
                          f"Expected 401, got {response.status_code}: {response.text}")
            return
        
        data = response.json()
        if "token" in data:
            result.add_fail("Test 3: Wrong OTP", "Token should NOT be present on wrong OTP")
            return
        
        result.add_pass("Test 3: Wrong OTP", "Correctly rejected with 401")
        
    except Exception as e:
        result.add_fail("Test 3: Wrong OTP", f"Exception: {str(e)}")

def test_non_otp_user(result: TestResult) -> Optional[str]:
    """Test 4: Non-OTP user should get direct token."""
    print(f"\n{BLUE}Test 4: Non-OTP user login (direct token){RESET}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": USER_EMAIL, "password": USER_PASSWORD},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 4: Non-OTP user login", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return None
        
        data = response.json()
        
        if data.get("otp_required"):
            result.add_fail("Test 4: Non-OTP user login", 
                          "otp_required should be false/absent for non-OTP user")
            return None
        
        if not data.get("token"):
            result.add_fail("Test 4: Non-OTP user login", "Missing token in response")
            return None
        
        if not data.get("user"):
            result.add_fail("Test 4: Non-OTP user login", "Missing user in response")
            return None
        
        if data["user"].get("role") != "user":
            result.add_fail("Test 4: Non-OTP user login", 
                          f"Expected role=user, got {data['user'].get('role')}")
            return None
        
        result.add_pass("Test 4: Non-OTP user login", 
                       f"Direct token received, user.role={data['user']['role']}")
        return data["token"]
        
    except Exception as e:
        result.add_fail("Test 4: Non-OTP user login", f"Exception: {str(e)}")
        return None

def test_toggle_otp(result: TestResult, admin_token: str):
    """Test 5: Toggle OTP for user, verify it works, then toggle back."""
    print(f"\n{BLUE}Test 5: Toggle OTP for user{RESET}")
    
    try:
        # Get list of users to find the 'user' operator
        response = requests.get(
            f"{BASE_URL}/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 5: Toggle OTP - list users", 
                          f"Expected 200, got {response.status_code}")
            return
        
        users = response.json()
        user_operator = None
        for u in users:
            if u.get("username") == "user" or u.get("email") == "user@factory.com":
                user_operator = u
                break
        
        if not user_operator:
            result.add_fail("Test 5: Toggle OTP", "Could not find 'user' operator")
            return
        
        user_id = user_operator["id"]
        print(f"  Found user operator: {user_id}")
        
        # Step 1: Enable OTP for user
        response = requests.patch(
            f"{BASE_URL}/users/{user_id}/otp",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"otp_login": True},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 5: Toggle OTP - enable", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return
        
        data = response.json()
        if not data.get("otp_login"):
            result.add_fail("Test 5: Toggle OTP - enable", 
                          f"otp_login should be true, got {data.get('otp_login')}")
            return
        
        print(f"  {GREEN}✓{RESET} OTP enabled for user")
        
        # Step 2: Try login - should now require OTP
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": USER_EMAIL, "password": USER_PASSWORD},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 5: Toggle OTP - login with OTP", 
                          f"Expected 200, got {response.status_code}")
            return
        
        data = response.json()
        if not data.get("otp_required"):
            result.add_fail("Test 5: Toggle OTP - login with OTP", 
                          "otp_required should be true after enabling OTP")
            return
        
        challenge_id = data.get("challenge_id")
        print(f"  {GREEN}✓{RESET} OTP now required for user login, challenge_id={challenge_id}")
        
        # Step 3: Read OTP and verify
        otp_code = read_otp_from_logs(challenge_id, "user@factory.com")
        if not otp_code:
            result.add_fail("Test 5: Toggle OTP - verify OTP", 
                          f"Could not find OTP in logs for challenge {challenge_id}")
            return
        
        response = requests.post(
            f"{BASE_URL}/auth/verify-otp",
            json={"challenge_id": challenge_id, "code": otp_code},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 5: Toggle OTP - verify OTP", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return
        
        data = response.json()
        if not data.get("token"):
            result.add_fail("Test 5: Toggle OTP - verify OTP", "Missing token")
            return
        
        print(f"  {GREEN}✓{RESET} OTP verification successful")
        
        # Step 4: Disable OTP for user
        response = requests.patch(
            f"{BASE_URL}/users/{user_id}/otp",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"otp_login": False},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 5: Toggle OTP - disable", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return
        
        data = response.json()
        if data.get("otp_login"):
            result.add_fail("Test 5: Toggle OTP - disable", 
                          f"otp_login should be false, got {data.get('otp_login')}")
            return
        
        print(f"  {GREEN}✓{RESET} OTP disabled for user")
        
        # Step 5: Verify login now returns direct token
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": USER_EMAIL, "password": USER_PASSWORD},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 5: Toggle OTP - final login", 
                          f"Expected 200, got {response.status_code}")
            return
        
        data = response.json()
        if data.get("otp_required"):
            result.add_fail("Test 5: Toggle OTP - final login", 
                          "otp_required should be false after disabling OTP")
            return
        
        if not data.get("token"):
            result.add_fail("Test 5: Toggle OTP - final login", "Missing token")
            return
        
        print(f"  {GREEN}✓{RESET} Direct token login restored")
        
        result.add_pass("Test 5: Toggle OTP for user", "All steps passed")
        
    except Exception as e:
        result.add_fail("Test 5: Toggle OTP", f"Exception: {str(e)}")

def test_create_restricted_user(result: TestResult, admin_token: str):
    """Test 6: Create restricted user with permissions."""
    print(f"\n{BLUE}Test 6: Create restricted user with permissions{RESET}")
    
    try:
        # Create user with newOrder permission
        response = requests.post(
            f"{BASE_URL}/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": "neworder@factory.com",
                "name": "New Order Only",
                "password": "order123",
                "role": "user",
                "username": "orderonly",
                "otp_login": False,
                "permissions": ["newOrder"]
            },
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 6: Create restricted user", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return
        
        data = response.json()
        
        if data.get("otp_login"):
            result.add_fail("Test 6: Create restricted user", 
                          f"otp_login should be false, got {data.get('otp_login')}")
            return
        
        if data.get("permissions") != ["newOrder"]:
            result.add_fail("Test 6: Create restricted user", 
                          f"Expected permissions=['newOrder'], got {data.get('permissions')}")
            return
        
        print(f"  {GREEN}✓{RESET} User created with permissions={data.get('permissions')}")
        
        # Login as the new user
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": "orderonly", "password": "order123"},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 6: Create restricted user - login", 
                          f"Expected 200, got {response.status_code}: {response.text}")
            return
        
        data = response.json()
        
        if data.get("otp_required"):
            result.add_fail("Test 6: Create restricted user - login", 
                          "otp_required should be false")
            return
        
        if not data.get("token"):
            result.add_fail("Test 6: Create restricted user - login", "Missing token")
            return
        
        token = data["token"]
        print(f"  {GREEN}✓{RESET} Login successful (direct token)")
        
        # Verify /auth/me shows permissions
        response = requests.get(
            f"{BASE_URL}/auth/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        
        if response.status_code != 200:
            result.add_fail("Test 6: Create restricted user - /auth/me", 
                          f"Expected 200, got {response.status_code}")
            return
        
        data = response.json()
        
        if data.get("permissions") != ["newOrder"]:
            result.add_fail("Test 6: Create restricted user - /auth/me", 
                          f"Expected permissions=['newOrder'], got {data.get('permissions')}")
            return
        
        print(f"  {GREEN}✓{RESET} /auth/me shows permissions={data.get('permissions')}")
        
        result.add_pass("Test 6: Create restricted user", "All steps passed")
        
    except Exception as e:
        result.add_fail("Test 6: Create restricted user", f"Exception: {str(e)}")

def test_invalid_permission(result: TestResult, admin_token: str):
    """Test 7: Invalid permission should return 400."""
    print(f"\n{BLUE}Test 7: Invalid permission on create{RESET}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": "invalid@factory.com",
                "name": "Invalid User",
                "password": "test123",
                "role": "user",
                "username": "invalid",
                "otp_login": False,
                "permissions": ["bogusKey"]
            },
            timeout=10
        )
        
        if response.status_code != 400:
            result.add_fail("Test 7: Invalid permission", 
                          f"Expected 400, got {response.status_code}: {response.text}")
            return
        
        result.add_pass("Test 7: Invalid permission", "Correctly rejected with 400")
        
    except Exception as e:
        result.add_fail("Test 7: Invalid permission", f"Exception: {str(e)}")

def test_patch_otp_nonexistent_user(result: TestResult, admin_token: str):
    """Test 8: PATCH OTP on non-existent user should return 404."""
    print(f"\n{BLUE}Test 8: PATCH OTP on non-existent user{RESET}")
    
    try:
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = requests.patch(
            f"{BASE_URL}/users/{fake_id}/otp",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"otp_login": True},
            timeout=10
        )
        
        if response.status_code != 404:
            result.add_fail("Test 8: PATCH OTP non-existent user", 
                          f"Expected 404, got {response.status_code}: {response.text}")
            return
        
        result.add_pass("Test 8: PATCH OTP non-existent user", "Correctly returned 404")
        
    except Exception as e:
        result.add_fail("Test 8: PATCH OTP non-existent user", f"Exception: {str(e)}")

def main():
    print(f"\n{'='*70}")
    print(f"Factory Order Management - Auth + OTP + Permissions Test Suite")
    print(f"Base URL: {BASE_URL}")
    print(f"{'='*70}\n")
    
    result = TestResult()
    
    # Test 1: Admin login OTP step 1
    challenge_data = test_admin_login_otp_step1(result)
    if not challenge_data:
        print(f"\n{RED}Cannot continue without admin challenge data{RESET}")
        result.summary()
        return 1
    
    # Test 2: Admin OTP verification
    admin_token = test_admin_verify_otp(result, challenge_data)
    if not admin_token:
        print(f"\n{RED}Cannot continue without admin token{RESET}")
        result.summary()
        return 1
    
    # Test 2b: Verify /auth/me
    test_admin_me(result, admin_token)
    
    # Test 3: Wrong OTP
    test_wrong_otp(result)
    
    # Test 4: Non-OTP user
    user_token = test_non_otp_user(result)
    
    # Test 5: Toggle OTP for user
    test_toggle_otp(result, admin_token)
    
    # Test 6: Create restricted user
    test_create_restricted_user(result, admin_token)
    
    # Test 7: Invalid permission
    test_invalid_permission(result, admin_token)
    
    # Test 8: PATCH OTP on non-existent user
    test_patch_otp_nonexistent_user(result, admin_token)
    
    # Summary
    success = result.summary()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
