"""
Test script for sas2py manifest integration
Tests APISIX sync and inference endpoint routing with SSL support
"""

import asyncio
import json
import sys
import os
from pathlib import Path

# Get project root (where .env is located)
project_root = Path(__file__).parent

# Add src to path for imports
sys.path.insert(0, str(project_root / "src"))

# Load environment variables from .env
from dotenv import load_dotenv
load_dotenv(project_root / '.env')

import httpx
from typing import Dict, Any
from apisix_client import APISIXClient

# Configuration from environment
FRONT_DOOR_URL = os.getenv("FRONT_DOOR_URL", "http://localhost:8080")
CONTROL_TOWER_URL = os.getenv("CONTROL_TOWER_URL", "http://localhost:8000")
APISIX_ADMIN_URL = os.getenv("APISIX_ADMIN_URL", "http://localhost:9180")
APISIX_ADMIN_KEY = os.getenv("APISIX_ADMIN_KEY", "edd1c9f034335f136f87ad84b625c8f1")

MANIFEST_ID = "sas2py"

async def create_http_client():
    """Create HTTP client with SSL configuration based on environment"""
    verify_ssl = os.getenv("VERIFY_SSL", "false").lower() == "true"
    
    if verify_ssl:
        # SSL enabled - disable verification for testing
        return httpx.AsyncClient(
            timeout=30.0,
            verify=False,  # Disable SSL verification for testing
            headers={
                "User-Agent": "DSP-FD2-Test/1.0",
                "Content-Type": "application/json"
            }
        )
    else:
        # HTTP - no SSL
        return httpx.AsyncClient(
            timeout=30.0,
            headers={
                "User-Agent": "DSP-FD2-Test/1.0", 
                "Content-Type": "application/json"
            }
        )

async def get_manifest_from_control_tower() -> Dict[str, Any]:
    """Get sas2py manifest from Control Tower"""
    print("\n1. Fetching manifest from Control Tower...")
    
    async with await create_http_client() as client:
        try:
            response = await client.get(f"{CONTROL_TOWER_URL}/manifests/{MANIFEST_ID}?resolve_env=true")
            
            if response.status_code == 200:
                manifest = response.json()
                print(f"  ✓ Manifest retrieved: {len(manifest.get('modules', []))} modules")
                return manifest
            else:
                print(f"  ✗ Failed to get manifest: {response.status_code}")
                print(f"  Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"  ✗ Error getting manifest: {str(e)}")
            return None

async def configure_apisix_directly(manifest: Dict[str, Any]):
    """Configure APISIX directly using APISIXClient"""
    print("\n2. Configuring APISIX directly from manifest...")
    
    # Debug: Check for APISIX modules
    modules = manifest.get("modules", [])
    apisix_modules = [m for m in modules if m.get("module_type") == "api_gateway" and "apisix" in m.get("name", "").lower()]
    print(f"  Found {len(apisix_modules)} APISIX modules")
    
    for mod in apisix_modules:
        config = mod.get("config", {})
        routes = config.get("routes", [])
        print(f"    - {mod.get('name')}: {len(routes)} routes")
        if routes:
            print(f"      First route: {routes[0].get('name', 'unknown')}")
    
    apisix_client = APISIXClient(APISIX_ADMIN_URL, APISIX_ADMIN_KEY)
    
    try:
        result = await apisix_client.configure_from_manifest(manifest)
        
        print(f"  ✓ Direct APISIX configuration complete")
        print(f"    Routes created: {len(result.get('routes', []))}")
        print(f"    Upstreams created: {len(result.get('upstreams', []))}")
        print(f"    Services created: {len(result.get('services', []))}")
        
        if result.get('errors'):
            print(f"    ⚠ Errors: {len(result['errors'])}")
            for error in result['errors']:
                print(f"      - {error}")
        
        await apisix_client.close()
        return len(result.get('errors', [])) == 0
        
    except Exception as e:
        print(f"  ✗ Direct config error: {str(e)}")
        import traceback
        traceback.print_exc()
        await apisix_client.close()
        return False

async def sync_apisix_from_manifest():
    """Sync APISIX configuration from Control Tower manifest via Front Door"""
    print("\n3. Syncing APISIX via Front Door...")
    
    async with await create_http_client() as client:
        try:
            response = await client.post(f"{FRONT_DOOR_URL}/admin/sync")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✓ Sync successful")
                print(f"    Status: {data.get('status')}")
                if 'projects' in data:
                    for mode, projects in data['projects'].items():
                        print(f"    {mode}: {len(projects)} projects")
                return True
            else:
                print(f"  ✗ Sync failed: {response.status_code}")
                print(f"    Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"  ✗ Sync error: {str(e)}")
            return False

async def verify_apisix_routes():
    """Verify APISIX routes are configured"""
    print("\n4. Verifying APISIX routes...")
    
    async with await create_http_client() as client:
        try:
            headers = {"X-API-KEY": APISIX_ADMIN_KEY}
            response = await client.get(
                f"{APISIX_ADMIN_URL}/apisix/admin/routes",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                routes = data.get("list", [])
                
                print(f"  ✓ Found {len(routes)} total routes")
                
                # Look for sas2py routes
                sas2py_routes = [r for r in routes if "sas2py" in r.get("value", {}).get("name", "").lower()]
                
                if sas2py_routes:
                    print(f"  ✓ Found {len(sas2py_routes)} sas2py routes:")
                    for route in sas2py_routes:
                        route_val = route.get("value", {})
                        print(f"    - {route_val.get('name')}: {route_val.get('uri')}")
                        
                        # Check for ai-prompt-template plugin
                        plugins = route_val.get("plugins", {})
                        if "ai-prompt-template" in plugins:
                            print(f"      ✓ ai-prompt-template plugin configured")
                        if "jwt-auth" in plugins:
                            print(f"      ✓ jwt-auth plugin configured")
                    
                    return True
                else:
                    print(f"  ⚠ No sas2py routes found")
                    return False
            else:
                print(f"  ✗ Failed to get routes: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ✗ Error verifying routes: {str(e)}")
            return False

async def get_jwt_token() -> str:
    """Get JWT token from JWT service"""
    print("\n5. Getting JWT token...")
    
    try:
        # Import JWT client
        from jwt_client import JWTClient
        
        # Use JWT service URL from environment or default
        jwt_service_url = os.getenv("JWT_SERVICE_URL", "http://localhost:5000")
        jwt_client = JWTClient(jwt_service_url)
        
        # Use the same secret that APISIX consumer is configured with
        jwt_secret = os.getenv("JWT_SECRET", "dev-secret-key")
        
        result = await jwt_client.generate_token(
            username="admin",
            password="password", 
            api_key="api_key_sas2py",
            custom_secret=jwt_secret
        )
        
        await jwt_client.close()
        
        if result.get("success"):
            token = result.get("access_token")
            print(f"  ✓ Token obtained from JWT service")
            return token
        else:
            print(f"  ✗ Failed to get token: {result.get('error')}")
            return None
            
    except Exception as e:
        print(f"  ✗ Token error: {str(e)}")
        return None

async def test_convert_endpoint(token: str):
    """Test the /api/sas2py/convert endpoint"""
    print("\n6. Testing convert endpoint...")
    
    async with await create_http_client() as client:
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "user_input": """
DATA work.example;
    INPUT name $ age salary;
    DATALINES;
John 30 50000
Jane 25 60000
;
RUN;

PROC MEANS DATA=work.example;
    VAR age salary;
RUN;
"""
            }
            
            response = await client.post(
                f"{FRONT_DOOR_URL}/sas2py/convert",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✓ Convert endpoint successful")
                print(f"    Response keys: {list(data.keys())}")
                return True
            else:
                print(f"  ✗ Convert failed: {response.status_code}")
                print(f"    Response: {response.text[:500]}")
                return False
                
        except Exception as e:
            print(f"  ✗ Convert error: {str(e)}")
            return False

async def test_test_endpoint(token: str):
    """Test the /api/sas2py/test endpoint"""
    print("\n7. Testing test generation endpoint...")
    
    async with await create_http_client() as client:
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "user_input": """
def add_numbers(a: int, b: int) -> int:
    return a + b

def multiply_numbers(a: int, b: int) -> int:
    return a * b
"""
            }
            
            response = await client.post(
                f"{FRONT_DOOR_URL}/sas2py/test",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✓ Test endpoint successful")
                print(f"    Response keys: {list(data.keys())}")
                return True
            else:
                print(f"  ✗ Test failed: {response.status_code}")
                print(f"    Response: {response.text[:500]}")
                return False
                
        except Exception as e:
            print(f"  ✗ Test error: {str(e)}")
            return False

async def verify_manifest_config():
    """Verify manifest configuration in Control Tower"""
    print("\n8. Verifying manifest configuration...")
    
    async with await create_http_client() as client:
        try:
            response = await client.get(f"{CONTROL_TOWER_URL}/manifests/{MANIFEST_ID}")
            
            if response.status_code == 200:
                manifest = response.json()
                print(f"  ✓ Manifest found")
                print(f"    Project: {manifest.get('project_name')}")
                print(f"    Environment: {manifest.get('environment')}")
                
                modules = manifest.get("modules", [])
                print(f"    Modules: {len(modules)}")
                
                # Check for required modules
                module_types = {m.get("module_type"): m.get("name") for m in modules}
                
                if "jwt_config" in module_types:
                    print(f"      ✓ JWT config: {module_types['jwt_config']}")
                
                inference_modules = [m for m in modules if m.get("module_type") == "inference_endpoint"]
                if inference_modules:
                    print(f"      ✓ Inference endpoints: {[m.get('name') for m in inference_modules]}")
                
                gateway_modules = [m for m in modules if m.get("module_type") == "api_gateway"]
                if gateway_modules:
                    print(f"      ✓ API gateways: {[m.get('name') for m in gateway_modules]}")
                
                return True
            else:
                print(f"  ✗ Manifest not found: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ✗ Manifest error: {str(e)}")
            return False

async def main():
    """Run all tests"""
    print("=" * 60)
    print("SAS2PY Manifest Integration Test")
    print("=" * 60)
    
    # Print configuration
    print(f"Front Door URL: {FRONT_DOOR_URL}")
    print(f"Control Tower URL: {CONTROL_TOWER_URL}")
    print(f"APISIX Admin URL: {APISIX_ADMIN_URL}")
    print(f"SSL Verification: {os.getenv('VERIFY_SSL', 'false')}")
    
    results = []
    
    # Verify manifest configuration
    results.append(await verify_manifest_config())
    
    # Get manifest for direct config
    manifest = await get_manifest_from_control_tower()
    if manifest:
        # Configure APISIX directly
        results.append(await configure_apisix_directly(manifest))
    else:
        print("⚠ Could not get manifest, skipping direct config")
        results.append(False)
    
    # Sync APISIX via Front Door
    results.append(await sync_apisix_from_manifest())
    
    # Verify routes
    results.append(await verify_apisix_routes())
    
    # Get token and test endpoints
    token = await get_jwt_token()
    if token:
        results.append(True)
        
        # Test endpoints
        results.append(await test_convert_endpoint(token))
        results.append(await test_test_endpoint(token))
    else:
        print("⚠ Could not get JWT token, skipping endpoint tests")
        results.extend([False, False])
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    test_names = [
        "Manifest Config",
        "Direct APISIX Config", 
        "Front Door Sync",
        "Route Verification",
        "JWT Token",
        "Convert Endpoint",
        "Test Endpoint"
    ]
    
    for i, (name, result) in enumerate(zip(test_names, results)):
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{i+1:2d}. {name:<20} {status}")
    
    passed = sum(results)
    total = len(results)
    print(f"\nPassed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed!")
    else:
        print(f"❌ {total - passed} test(s) failed")
    
    return passed == total

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
