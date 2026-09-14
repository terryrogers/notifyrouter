import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "php" / "app.php").read_text(encoding="utf-8")
CONSOLE = (ROOT / "php" / "admin-console.php").read_text(encoding="utf-8")


class AdministrationConsoleContractTests(unittest.TestCase):
    def test_favicon_and_semantic_ui_are_application_wide(self):
        self.assertIn('/assets/favicon.svg', APP)
        self.assertIn('semantic-ui-css@2.5.0', APP)
        self.assertTrue((ROOT / "php" / "assets" / "favicon.svg").is_file())

    def test_release_identity_and_attribution_are_linked_safely(self):
        self.assertIn("const NOTIFYROUTER_VERSION = '0.4.2'", APP)
        self.assertIn("releases/tag/v0.4.2", APP)
        self.assertIn('target="_blank" rel="noopener noreferrer">NotifyRouter</a>', APP)
        self.assertIn('target="_blank" rel="noopener noreferrer">v\'.NOTIFYROUTER_VERSION', APP)
        self.assertIn('target="_blank" rel="noopener noreferrer">Terry Rogers</a> © \'.date(\'Y\')', APP)

    def test_account_navigation_and_panels_resist_semantic_ui_regressions(self):
        self.assertIn("function can_access_administration()", APP)
        self.assertIn("function refresh_session_authorization()", APP)
        self.assertRegex(
            APP,
            r'\/admin/settings.*Settings.*href="\/admin">Administration.*Sign Out',
        )
        self.assertIn('class="nav-avatar"', APP)
        self.assertNotIn('class="avatar" src="<?=h(profile_url())?>"', APP)
        stylesheet = (ROOT / "php" / "assets" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".ui.segment.card{display:block;width:100%;max-width:none", stylesheet)
        self.assertIn(".ui.segment.card.narrow{max-width:440px", stylesheet)

    def test_administration_navigation_contains_every_requested_section(self):
        for label in (
            "Overview", "Users", "Roles & Permissions", "Service Health",
            "Destinations", "Security", "Email", "Log",
        ):
            self.assertIn(label, CONSOLE)

    def test_production_entry_points_do_not_depend_on_rewrite_rules(self):
        for entry_point in (
            ROOT / "php" / "index.php",
            ROOT / "php" / "admin" / "index.php",
            ROOT / "php" / "admin" / "settings" / "index.php",
            ROOT / "php" / "admin" / "forgot" / "index.php",
            ROOT / "php" / "admin" / "reset" / "index.php",
            ROOT / "php" / "admin" / "inspect" / "index.php",
            ROOT / "php" / "profile-image" / "index.php",
            ROOT / "php" / "webhook" / "index.php",
        ):
            self.assertTrue(entry_point.is_file(), str(entry_point))
        self.assertNotIn("/admin/administration", APP + CONSOLE)

    def test_permissions_match_the_administration_contract(self):
        for permission in (
            "Read-only Administrator", "Read-only", "Administrator",
            "Manage Inbound Rules", "Manage Outbound Templates",
            "View Recent Events", "Clear Recent Events", "View Payload Log",
            "Clear Payload Log",
        ):
            self.assertIn(permission, APP)

    def test_rules_templates_and_destinations_are_separate_models(self):
        self.assertIn('CREATE TABLE IF NOT EXISTS rules', APP)
        self.assertIn('CREATE TABLE IF NOT EXISTS outbound_templates', APP)
        self.assertIn('CREATE TABLE IF NOT EXISTS destinations', APP)
        self.assertNotIn('migrate_embedded_templates', APP)
        self.assertNotIn('Migrated from the original combined rule', APP)
        self.assertIn("'Inbound Rules'", CONSOLE)
        self.assertIn("'Outbound Templates'", CONSOLE)

    def test_audit_events_cover_requested_security_and_delivery_events(self):
        for event in (
            "Login", "Logout", "Password Reset Request", "Password Change",
            "Configuration Change", "Webhook Received", "Message Sent",
        ):
            self.assertIn(event, APP)


if __name__ == "__main__":
    unittest.main()
