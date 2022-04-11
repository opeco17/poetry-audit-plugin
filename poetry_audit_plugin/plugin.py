from poetry.console.application import Application
from poetry.plugins.application_plugin import ApplicationPlugin

from poetry_audit_plugin.command import factory


class AuditApplicationPlugin(ApplicationPlugin):
    def activate(self, application: Application) -> None:
        application.command_loader.register_factory("audit", factory)
