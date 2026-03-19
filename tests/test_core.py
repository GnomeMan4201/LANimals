import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def test_nexus_db_imports():
    from core import nexus_db
    assert nexus_db is not None

def test_nexus_models_imports():
    from core import nexus_models
    assert nexus_models is not None

def test_modules_import():
    from modules import arp_recon
    assert arp_recon is not None
