import sys
import os

# Add root folder to sys.path so engine and modules resolve cleanly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app