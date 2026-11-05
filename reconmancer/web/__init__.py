from __future__ import annotations


def register_web_blueprints(app) -> None:
    from reconmancer.web.runs import runs_blueprint
    from reconmancer.web.storage import storage_blueprint
    from reconmancer.web.settings import settings_blueprint
    from reconmancer.web.auth_profiles import auth_profiles_blueprint
    from reconmancer.web.auth_execution import auth_execution_blueprint
    from reconmancer.web.auth_handoffs import auth_handoffs_blueprint
    from reconmancer.web.findings import findings_blueprint
    from reconmancer.web.analysis import analysis_blueprint
    from reconmancer.web.traffic_evidence import traffic_evidence_blueprint
    from reconmancer.web.jobs import jobs_blueprint
    from reconmancer.web.selection_handoffs import selection_handoffs_blueprint
    from reconmancer.web.projects import projects_blueprint

    for blueprint in (
        runs_blueprint,
        storage_blueprint,
        settings_blueprint,
        auth_profiles_blueprint,
        auth_execution_blueprint,
        auth_handoffs_blueprint,
        findings_blueprint,
        analysis_blueprint,
        traffic_evidence_blueprint,
        jobs_blueprint,
        selection_handoffs_blueprint,
        projects_blueprint,
    ):
        app.register_blueprint(blueprint)
