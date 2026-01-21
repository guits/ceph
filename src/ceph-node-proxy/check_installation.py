#!/usr/bin/env python3
"""
Installation checker for Ceph Node Proxy

This script verifies that all components are properly installed and configured.
Run this after the refactoring to ensure everything is working correctly.
"""
import sys
import os


def print_header(title):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def check_python_version():
    """Check Python version."""
    print("🐍 Checking Python version...")
    version = sys.version_info
    if version >= (3, 9):
        print(f"   ✅ Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"   ❌ Python {version.major}.{version.minor}.{version.micro} (Requires 3.9+)")
        return False


def check_dependencies():
    """Check required dependencies."""
    print("\n📦 Checking dependencies...")
    
    deps = {
        'yaml': 'PyYAML',
        'cherrypy': 'CherryPy',
    }
    
    all_ok = True
    for module, package in deps.items():
        try:
            __import__(module)
            print(f"   ✅ {package}")
        except ImportError:
            print(f"   ❌ {package} (Not installed)")
            print(f"      Install with: pip install {package}")
            all_ok = False
    
    return all_ok


def check_modules():
    """Check that new modules can be imported."""
    print("\n🔧 Checking new modules...")
    
    modules = [
        'ceph_node_proxy.config',
        'ceph_node_proxy.api_server',
        'ceph_node_proxy.led_handler',
        'ceph_node_proxy.main',
        'ceph_node_proxy.api',
    ]
    
    all_ok = True
    for module in modules:
        try:
            __import__(module)
            print(f"   ✅ {module}")
        except ImportError as e:
            print(f"   ❌ {module}")
            print(f"      Error: {e}")
            all_ok = False
    
    return all_ok


def check_files():
    """Check that all required files exist."""
    print("\n📄 Checking files...")
    
    required_files = [
        'ceph_node_proxy/config.py',
        'ceph_node_proxy/api_server.py',
        'ceph_node_proxy/led_handler.py',
        'ceph_node_proxy/main.py',
        'ceph_node_proxy/api.py',
        'README.md',
        'ARCHITECTURE.md',
        'MIGRATION_GUIDE.md',
        'REFACTORING_SUMMARY.md',
        'requirements.txt',
        'node-proxy.yml.example',
    ]
    
    all_ok = True
    for file in required_files:
        if os.path.exists(file):
            print(f"   ✅ {file}")
        else:
            print(f"   ❌ {file} (Missing)")
            all_ok = False
    
    return all_ok


def check_config_example():
    """Check configuration example."""
    print("\n⚙️  Checking configuration example...")
    
    if os.path.exists('node-proxy.yml.example'):
        print("   ✅ Configuration example exists")
        print("   💡 Copy to /etc/ceph/node-proxy.yml and customize")
        return True
    else:
        print("   ❌ Configuration example not found")
        return False


def check_documentation():
    """Check documentation completeness."""
    print("\n📚 Checking documentation...")
    
    docs = {
        'README.md': 'Main documentation',
        'ARCHITECTURE.md': 'Architecture details',
        'MIGRATION_GUIDE.md': 'Migration guide',
        'REFACTORING_SUMMARY.md': 'Refactoring summary',
        'CHANGES.md': 'Changelog',
    }
    
    all_ok = True
    for doc, description in docs.items():
        if os.path.exists(doc):
            size = os.path.getsize(doc)
            print(f"   ✅ {doc:30} ({size:6} bytes) - {description}")
        else:
            print(f"   ❌ {doc:30} - {description}")
            all_ok = False
    
    return all_ok


def check_tests():
    """Check test files."""
    print("\n🧪 Checking tests...")
    
    if os.path.exists('tests_example.py'):
        print("   ✅ tests_example.py exists")
        print("   💡 Run with: python tests_example.py")
        return True
    else:
        print("   ❌ tests_example.py not found")
        return False


def print_summary(results):
    """Print summary of checks."""
    print_header("SUMMARY")
    
    total = len(results)
    passed = sum(1 for r in results.values() if r)
    failed = total - passed
    
    for check, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status} - {check}")
    
    print(f"\n   Total: {passed}/{total} checks passed")
    
    if failed == 0:
        print("\n   🎉 All checks passed! Installation is complete.")
        print("\n   Next steps:")
        print("   1. Install dependencies: pip install -r requirements.txt")
        print("   2. Copy config: cp node-proxy.yml.example /etc/ceph/node-proxy.yml")
        print("   3. Edit config: vi /etc/ceph/node-proxy.yml")
        print("   4. Run tests: python tests_example.py")
        print("   5. Start service: python -m ceph_node_proxy.main --config /path/to/config.json")
        return True
    else:
        print(f"\n   ⚠️  {failed} check(s) failed. Please fix the issues above.")
        return False


def main():
    """Main entry point."""
    print_header("Ceph Node Proxy - Installation Checker")
    print("This script verifies that the refactoring was successful")
    print("and all components are properly installed.")
    
    results = {}
    
    # Run all checks
    results['Python Version'] = check_python_version()
    results['Dependencies'] = check_dependencies()
    results['Modules'] = check_modules()
    results['Files'] = check_files()
    results['Config Example'] = check_config_example()
    results['Documentation'] = check_documentation()
    results['Tests'] = check_tests()
    
    # Print summary
    success = print_summary(results)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Check interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
