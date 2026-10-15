"""
TenantShield - Comprehensive Tenant Isolation & RLS Test Suite
=============================================================
Enforces and verifies multi-tenant database security at Level 2:
1. Current role is strictly 'tenantshield_app'.
2. Role lacks SUPERUSER, BYPASSRLS, CREATEDB, CREATEROLE.
3. Role does not own tables and has no elevated role memberships.
4. RLS is enabled and forced on 'documents'.
5. Policy 'tenant_isolation_policy' exists with correct USING and WITH CHECK.
6. Acme can read its own documents.
7. Acme cannot read Beta documents (including direct ID lookup).
8. Beta can read its own documents and cannot read Acme documents.
9. Acme cannot insert a document belonging to Beta.
10. Beta cannot insert a document belonging to Acme.
11. Cross-tenant UPDATE and DELETE do not modify another tenant's rows.
12. Unauthenticated session sees zero documents and cannot insert.
13. Transaction-local context does not leak across transactions.
14. Legitimate same-tenant CRUD operations work as expected.
15. Application role cannot CREATE or DROP tables.
"""

from contextlib import asynccontextmanager
from uuid import UUID, uuid4
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.database import set_tenant_context

# For tests, use NullPool to ensure connections are strictly tied to each test's event loop
test_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


@asynccontextmanager
async def isolated_tenant_session(tenant_id: UUID | str):
    """
    Provides a transaction-local session setting 'app.current_tenant_id'
    using is_local=true so it resets automatically on commit/rollback.
    """
    async with TestSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_id)
            yield session


@pytest_asyncio.fixture(scope="function")
async def tenant_fixtures():
    """
    Resolves existing Acme and Beta tenants along with representative document IDs.
    Runs strictly under tenantshield_app.
    """
    async with TestSessionLocal() as session:
        # Retrieve tenants (tenantshield_app has SELECT on tenants)
        acme_res = await session.execute(
            text("SELECT id FROM tenants WHERE slug = 'acme'")
        )
        acme_id = acme_res.scalar_one()

        beta_res = await session.execute(
            text("SELECT id FROM tenants WHERE slug = 'beta'")
        )
        beta_id = beta_res.scalar_one()

    # Get sample document IDs within respective tenant contexts
    async with isolated_tenant_session(acme_id) as session:
        acme_doc_res = await session.execute(
            text("SELECT id FROM documents WHERE tenant_id = :tenant_id LIMIT 1"),
            {"tenant_id": str(acme_id)},
        )
        acme_doc_id = acme_doc_res.scalar_one()

    async with isolated_tenant_session(beta_id) as session:
        beta_doc_res = await session.execute(
            text("SELECT id FROM documents WHERE tenant_id = :tenant_id LIMIT 1"),
            {"tenant_id": str(beta_id)},
        )
        beta_doc_id = beta_doc_res.scalar_one()

    return {
        "acme_id": acme_id,
        "beta_id": beta_id,
        "acme_doc_id": acme_doc_id,
        "beta_doc_id": beta_doc_id,
    }


# ------------------------------------------------------------------------------
# 1. Database Role Verification
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_01_current_role_is_tenantshield_app():
    """Verify that every application query runs as 'tenantshield_app'."""
    async with TestSessionLocal() as session:
        user_res = await session.execute(text("SELECT current_user"))
        current_user = user_res.scalar_one()
        assert current_user == "tenantshield_app", (
            f"Expected connection role 'tenantshield_app', got '{current_user}'"
        )


@pytest.mark.asyncio
async def test_02_role_lacks_elevated_privileges():
    """Verify role has NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, and NOCREATEROLE."""
    async with TestSessionLocal() as session:
        role_res = await session.execute(
            text("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = 'tenantshield_app'")
        )
        rolsuper, rolbypassrls, rolcreatedb, rolcreaterole = role_res.fetchone()
        assert rolsuper is False, "Role must NOT be superuser"
        assert rolbypassrls is False, "Role must NOT have BYPASSRLS"
        assert rolcreatedb is False, "Role must NOT have CREATEDB"
        assert rolcreaterole is False, "Role must NOT have CREATEROLE"


@pytest.mark.asyncio
async def test_03_role_does_not_own_tables_and_has_no_privileged_memberships():
    """Verify role does not own documents and has no privileged memberships."""
    async with TestSessionLocal() as session:
        # Check table owner
        owner_res = await session.execute(
            text("SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'documents'")
        )
        owner = owner_res.scalar_one()
        assert owner != "tenantshield_app", "Application role must NOT own the documents table"

        # Check role memberships
        memberships_res = await session.execute(
            text(
                "SELECT m.rolname FROM pg_roles r "
                "JOIN pg_auth_members am ON r.oid = am.member "
                "JOIN pg_roles m ON am.roleid = m.oid "
                "WHERE r.rolname = 'tenantshield_app'"
            )
        )
        memberships = [row[0] for row in memberships_res.fetchall()]
        assert "postgres" not in memberships
        assert "pg_read_all_data" not in memberships
        assert "pg_write_all_data" not in memberships


# ------------------------------------------------------------------------------
# 2. Row-Level Security Configuration
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_04_documents_rls_is_enabled_and_forced():
    """Verify RLS is both ENABLED and FORCED on documents table."""
    async with TestSessionLocal() as session:
        class_res = await session.execute(
            text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'documents'")
        )
        row = class_res.fetchone()
        assert row is not None, "Table 'documents' not found"
        relrowsecurity, relforcerowsecurity = row
        assert relrowsecurity is True, "RLS must be enabled on documents table"
        assert relforcerowsecurity is True, "RLS must be forced on documents table"


@pytest.mark.asyncio
async def test_05_policy_definition_and_conditions():
    """Verify tenant_isolation_policy exists with correct USING and WITH CHECK."""
    async with TestSessionLocal() as session:
        policy_res = await session.execute(
            text(
                "SELECT policyname, cmd, qual, with_check FROM pg_policies "
                "WHERE tablename = 'documents' AND policyname = 'tenant_isolation_policy'"
            )
        )
        policy = policy_res.fetchone()
        assert policy is not None, "Policy 'tenant_isolation_policy' must exist on documents"
        policyname, cmd, qual, with_check = policy
        assert cmd in ("ALL", "*"), f"Policy should apply to ALL operations, got {cmd}"
        assert "app.current_tenant_id" in qual, "USING clause must reference 'app.current_tenant_id'"
        assert "app.current_tenant_id" in with_check, "WITH CHECK clause must reference 'app.current_tenant_id'"
        assert "tenant_id" in qual, "USING clause must reference 'tenant_id'"
        assert "tenant_id" in with_check, "WITH CHECK clause must reference 'tenant_id'"


# ------------------------------------------------------------------------------
# 3. Read Isolation Tests
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_06_acme_reads_own_documents(tenant_fixtures):
    """Verify Acme can read its own documents."""
    acme_id = tenant_fixtures["acme_id"]
    async with isolated_tenant_session(acme_id) as session:
        result = await session.execute(text("SELECT id, title, tenant_id FROM documents"))
        docs = result.fetchall()
        assert len(docs) >= 2, "Acme should see its documents"
        for doc in docs:
            assert doc.tenant_id == acme_id, "Returned document must belong to Acme"


@pytest.mark.asyncio
async def test_07_acme_cannot_read_beta_documents(tenant_fixtures):
    """Verify Acme cannot read Beta documents, including direct ID lookup."""
    acme_id = tenant_fixtures["acme_id"]
    beta_id = tenant_fixtures["beta_id"]
    beta_doc_id = tenant_fixtures["beta_doc_id"]

    async with isolated_tenant_session(acme_id) as session:
        # Filter query for Beta documents
        beta_query = await session.execute(
            text("SELECT count(*) FROM documents WHERE tenant_id = :beta_id"),
            {"beta_id": str(beta_id)},
        )
        assert beta_query.scalar_one() == 0, "Acme must see 0 Beta documents"

        # Direct ID lookup (IDOR defense)
        direct_lookup = await session.execute(
            text("SELECT id FROM documents WHERE id = :beta_doc_id"),
            {"beta_doc_id": str(beta_doc_id)},
        )
        assert direct_lookup.fetchone() is None, "Acme must not be able to read Beta document by ID"


@pytest.mark.asyncio
async def test_08_beta_reads_own_documents_and_cannot_read_acme(tenant_fixtures):
    """Verify Beta can read its own documents and cannot read Acme documents."""
    acme_id = tenant_fixtures["acme_id"]
    beta_id = tenant_fixtures["beta_id"]
    acme_doc_id = tenant_fixtures["acme_doc_id"]

    async with isolated_tenant_session(beta_id) as session:
        # Read Beta docs
        result = await session.execute(text("SELECT id, title, tenant_id FROM documents"))
        docs = result.fetchall()
        assert len(docs) >= 2, "Beta should see its documents"
        for doc in docs:
            assert doc.tenant_id == beta_id, "Returned document must belong to Beta"

        # Cannot read Acme docs
        acme_query = await session.execute(
            text("SELECT count(*) FROM documents WHERE tenant_id = :acme_id"),
            {"acme_id": str(acme_id)},
        )
        assert acme_query.scalar_one() == 0, "Beta must see 0 Acme documents"

        # Direct ID lookup
        direct_lookup = await session.execute(
            text("SELECT id FROM documents WHERE id = :acme_doc_id"),
            {"acme_doc_id": str(acme_doc_id)},
        )
        assert direct_lookup.fetchone() is None, "Beta must not be able to read Acme document by ID"


# ------------------------------------------------------------------------------
# 4. Write Isolation Tests (Insert, Update, Delete)
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_09_acme_cannot_insert_beta_document(tenant_fixtures):
    """Verify Acme context cannot insert a document stamped with Beta's tenant_id."""
    acme_id = tenant_fixtures["acme_id"]
    beta_id = tenant_fixtures["beta_id"]

    async with isolated_tenant_session(acme_id) as session:
        with pytest.raises(DBAPIError) as exc_info:
            await session.execute(
                text(
                    "INSERT INTO documents (tenant_id, title, content) "
                    "VALUES (:tenant_id, 'Injected Beta Doc', 'Blocked by RLS WITH CHECK')"
                ),
                {"tenant_id": str(beta_id)},
            )
        err_msg = str(exc_info.value).lower()
        assert "violates row-level security policy" in err_msg or "check violation" in err_msg


@pytest.mark.asyncio
async def test_10_beta_cannot_insert_acme_document(tenant_fixtures):
    """Verify Beta context cannot insert a document stamped with Acme's tenant_id."""
    acme_id = tenant_fixtures["acme_id"]
    beta_id = tenant_fixtures["beta_id"]

    async with isolated_tenant_session(beta_id) as session:
        with pytest.raises(DBAPIError) as exc_info:
            await session.execute(
                text(
                    "INSERT INTO documents (tenant_id, title, content) "
                    "VALUES (:tenant_id, 'Injected Acme Doc', 'Blocked by RLS WITH CHECK')"
                ),
                {"tenant_id": str(acme_id)},
            )
        err_msg = str(exc_info.value).lower()
        assert "violates row-level security policy" in err_msg or "check violation" in err_msg


@pytest.mark.asyncio
async def test_11_cross_tenant_update_and_delete_prevented(tenant_fixtures):
    """Verify Acme context cannot update or delete Beta documents."""
    acme_id = tenant_fixtures["acme_id"]
    beta_id = tenant_fixtures["beta_id"]
    beta_doc_id = tenant_fixtures["beta_doc_id"]

    # 1. Acme attempts to update Beta's document
    async with isolated_tenant_session(acme_id) as session:
        update_res = await session.execute(
            text("UPDATE documents SET title = 'Acme Tampered Title' WHERE id = :beta_doc_id"),
            {"beta_doc_id": str(beta_doc_id)},
        )
        assert update_res.rowcount == 0, "Cross-tenant UPDATE must affect 0 rows"

    # 2. Acme attempts to delete Beta's document
    async with isolated_tenant_session(acme_id) as session:
        delete_res = await session.execute(
            text("DELETE FROM documents WHERE id = :beta_doc_id"),
            {"beta_doc_id": str(beta_doc_id)},
        )
        assert delete_res.rowcount == 0, "Cross-tenant DELETE must affect 0 rows"

    # 3. Confirm Beta document remains intact
    async with isolated_tenant_session(beta_id) as session:
        doc_res = await session.execute(
            text("SELECT title FROM documents WHERE id = :beta_doc_id"),
            {"beta_doc_id": str(beta_doc_id)},
        )
        row = doc_res.fetchone()
        assert row is not None, "Beta document must still exist"
        assert row[0] != "Acme Tampered Title", "Beta document title must not be altered"


# ------------------------------------------------------------------------------
# 5. Unauthenticated Context & Context Leakage Tests
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_12_unauthenticated_session_cannot_read_or_insert(tenant_fixtures):
    """Verify session with no tenant context set sees 0 documents and cannot insert."""
    acme_id = tenant_fixtures["acme_id"]

    async with TestSessionLocal() as session:
        async with session.begin():
            # Query without context
            count_res = await session.execute(text("SELECT count(*) FROM documents"))
            assert count_res.scalar_one() == 0, "Unset context must see 0 documents"

            # Attempt insert without context
            with pytest.raises(DBAPIError) as exc_info:
                await session.execute(
                    text(
                        "INSERT INTO documents (tenant_id, title, content) "
                        "VALUES (:tenant_id, 'Unauthed Doc', 'Should fail RLS')"
                    ),
                    {"tenant_id": str(acme_id)},
                )
            err_msg = str(exc_info.value).lower()
            assert "violates row-level security policy" in err_msg or "check violation" in err_msg


@pytest.mark.asyncio
async def test_13_transaction_local_context_does_not_leak():
    """Verify transaction-local tenant context resets completely when transaction ends."""
    async with TestSessionLocal() as session:
        # Phase 1: Set Acme context in Transaction 1
        async with session.begin():
            res = await session.execute(text("SELECT id FROM tenants WHERE slug = 'acme'"))
            acme_id = res.scalar_one()
            await session.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
                {"tenant_id": str(acme_id)},
            )
            acme_count = (await session.execute(text("SELECT count(*) FROM documents"))).scalar_one()
            assert acme_count >= 2, "Acme should see its documents inside transaction"

        # Phase 2: Transaction 2 on same session without setting context
        async with session.begin():
            ctx_res = await session.execute(
                text("SELECT current_setting('app.current_tenant_id', true)")
            )
            ctx = ctx_res.scalar_one()
            assert ctx == "" or ctx is None, f"Context leaked across transactions: {ctx}"
            clean_count = (await session.execute(text("SELECT count(*) FROM documents"))).scalar_one()
            assert clean_count == 0, "Subsequent transaction saw documents from leaked context"


# ------------------------------------------------------------------------------
# 6. Legitimate CRUD & Privileges Tests
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_14_legitimate_same_tenant_operations_work(tenant_fixtures):
    """Verify that same-tenant INSERT, UPDATE, and DELETE work correctly."""
    acme_id = tenant_fixtures["acme_id"]

    async with isolated_tenant_session(acme_id) as session:
        # 1. Insert new Acme doc
        new_doc_res = await session.execute(
            text(
                "INSERT INTO documents (tenant_id, title, content) "
                "VALUES (:tenant_id, 'Acme Test Doc', 'Valid content') "
                "RETURNING id"
            ),
            {"tenant_id": str(acme_id)},
        )
        new_doc_id = new_doc_res.scalar_one()

        # 2. Update doc
        update_res = await session.execute(
            text("UPDATE documents SET title = 'Acme Updated Doc' WHERE id = :id"),
            {"id": str(new_doc_id)},
        )
        assert update_res.rowcount == 1, "Legitimate UPDATE must affect 1 row"

        # 3. Read back updated doc
        read_res = await session.execute(
            text("SELECT title FROM documents WHERE id = :id"),
            {"id": str(new_doc_id)},
        )
        assert read_res.scalar_one() == "Acme Updated Doc"

        # 4. Delete doc
        delete_res = await session.execute(
            text("DELETE FROM documents WHERE id = :id"),
            {"id": str(new_doc_id)},
        )
        assert delete_res.rowcount == 1, "Legitimate DELETE must affect 1 row"


@pytest.mark.asyncio
async def test_15_role_cannot_create_or_drop_tables():
    """Verify application role has no DDL permissions (cannot CREATE or DROP tables)."""
    async with TestSessionLocal() as session:
        # Cannot CREATE table
        with pytest.raises(DBAPIError) as exc_create:
            async with session.begin():
                await session.execute(text("CREATE TABLE malicious_test (id int)"))
        assert "permission denied" in str(exc_create.value).lower()

        # Cannot DROP table
        with pytest.raises(DBAPIError) as exc_drop:
            async with session.begin():
                await session.execute(text("DROP TABLE documents"))
        assert "must be owner" in str(exc_drop.value).lower() or "permission denied" in str(exc_drop.value).lower()
