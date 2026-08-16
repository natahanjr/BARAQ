import os
import json
import logging
from typing import List, Dict, Any, Callable
from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal

logger = logging.getLogger("baraq.apps")

class BaraqApp:
    """
    Represents a modular extension to BARAQ.
    An app can provide detection rules, custom API endpoints, or dashboard widgets.
    """
    def __init__(self, name: str, version: str, description: str):
        self.name = name
        self.version = version
        self.description = description
        self.rules: List[Callable] = []
        self.endpoints: List[Dict[str, Any]] = []

    def register_rule(self, rule_func: Callable):
        self.rules.append(rule_func)

class AppManager:
    """
    Manages the lifecycle of BARAQ Apps.
    """
    def __init__(self, apps_dir: str = "backend/apps"):
        self.apps_dir = apps_dir
        self.loaded_apps: Dict[str, BaraqApp] = {}
        if not os.path.exists(self.apps_dir):
            os.makedirs(self.apps_dir)

    def load_apps(self):
        """Scans the apps directory for app definitions (currently simplified as Python modules)."""
        logger.info("Loading BARAQ Apps from %s...", self.apps_dir)
        # In a full implementation, this would dynamically import modules from the apps_dir
        # For now, we provide the framework for modularity.
        pass

    def get_all_rules(self) -> List[Callable]:
        all_rules = []
        for app in self.loaded_apps.values():
            all_rules.extend(app.rules)
        return all_rules

app_manager = AppManager()