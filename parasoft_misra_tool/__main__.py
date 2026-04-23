"""Allow running as: python -m parasoft_misra_tool"""
import sys
from .main import main

sys.exit(main())
