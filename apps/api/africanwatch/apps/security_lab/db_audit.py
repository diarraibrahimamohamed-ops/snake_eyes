from __future__ import annotations
import os
import re
import time


def _env_name(profile: str, organization_id) -> str:
    safe = re.sub(r"[^A-Z0-9_]", "_", profile.upper())
    org = re.sub(r"[^A-Z0-9]", "", str(organization_id).upper())
    return f"SECURITY_DB_DSN_{org}_{safe}"


def postgres_posture(profile: str, organization_id) -> dict:
    env_name = _env_name(profile, organization_id)
    dsn = os.getenv(env_name, "")
    if not dsn:
        raise ValueError(f"Profil DB absent côté serveur pour cette organisation: {profile}")
    if not dsn.startswith("postgresql://") and not dsn.startswith("postgres://"):
        raise ValueError("Seuls les profils PostgreSQL sont supportés par cet audit en lecture seule.")
    import psycopg2
    start = time.monotonic()
    conn = psycopg2.connect(dsn, connect_timeout=5, options="-c statement_timeout=5000")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT version(), current_database(), current_user, current_setting('ssl', true)")
            version, dbname, user, ssl = cur.fetchone()
            cur.execute("SELECT count(*) FROM pg_roles WHERE rolcanlogin AND rolsuper")
            superusers = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM pg_roles WHERE rolcanlogin AND rolcreaterole")
            role_admins = int(cur.fetchone()[0])
            cur.execute("SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND has_schema_privilege('public', nspname, 'CREATE')")
            public_create_schemas = [row[0] for row in cur.fetchall()]
            cur.execute("SELECT count(*) FROM pg_roles WHERE rolcanlogin AND (rolbypassrls OR rolcreatedb)")
            privileged_login_roles = int(cur.fetchone()[0])
        findings = []
        if str(ssl).lower() != "on":
            findings.append({"severity": "high", "category": "database-crypto", "title": "SSL PostgreSQL non observé", "description": "La session d'audit n'indique pas SSL=on.", "evidence": {"ssl": ssl}, "remediation": "Activer TLS pour les connexions distantes et contrôler pg_hba.conf."})
        if superusers > 2:
            findings.append({"severity": "medium", "category": "database-privilege", "title": "Nombre élevé de superusers", "description": "Plusieurs comptes de connexion possèdent le privilège superuser.", "evidence": {"count": superusers}, "remediation": "Réduire les superusers aux comptes d'administration indispensables."})
        if public_create_schemas:
            findings.append({"severity": "medium", "category": "database-privilege", "title": "CREATE public sur des schémas applicatifs", "description": "PUBLIC dispose de CREATE sur un ou plusieurs schémas non système.", "evidence": {"schemas": public_create_schemas[:20]}, "remediation": "Retirer CREATE à PUBLIC lorsque ce privilège n'est pas requis."})
        if role_admins > 2:
            findings.append({"severity": "low", "category": "database-privilege", "title": "Plusieurs comptes peuvent créer des rôles", "description": "Plusieurs comptes de connexion possèdent rolcreaterole.", "evidence": {"count": role_admins}, "remediation": "Appliquer le principe du moindre privilège."})
        return {"engine": "postgresql", "database": dbname, "current_user": user, "version": str(version)[:200], "ssl": ssl, "superuser_logins": superusers, "role_admin_logins": role_admins, "privileged_login_roles": privileged_login_roles, "public_create_schemas": public_create_schemas[:20], "findings": findings, "duration_seconds": round(time.monotonic()-start, 3)}
    finally:
        conn.close()
