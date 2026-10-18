/**
 * TenantShield Client Application Logic
 * =====================================
 * Security Principles:
 * 1. In-memory authentication token only (never persisted to localStorage/sessionStorage).
 * 2. Strict DOM manipulation using textContent and createElement (zero innerHTML).
 * 3. Tenant ID is never supplied by the client on creation/updates; derived server-side.
 * 4. Automatic session termination on HTTP 401.
 * 5. Button disabling during network operations.
 */

(function () {
  'use strict';

  // --- In-Memory State ---
  var authToken = null;
  var currentUser = null;
  var pendingDeleteDocId = null;

  // --- DOM Elements ---
  var appHeader = document.getElementById('app-header');
  var headerMeta = document.getElementById('header-user-meta');
  var headerEmail = document.getElementById('header-email');
  var headerTenant = document.getElementById('header-tenant');
  var btnSignout = document.getElementById('btn-signout');

  var loginView = document.getElementById('login-view');
  var loginForm = document.getElementById('login-form');
  var loginEmailInput = document.getElementById('login-email');
  var loginPassInput = document.getElementById('login-password');
  var btnLoginSubmit = document.getElementById('btn-login-submit');
  var loginError = document.getElementById('login-error');

  var appShell = document.getElementById('app-shell');
  var sidebarNav = document.getElementById('sidebar-nav');

  // Tenant Workspace Views
  var tenantWorkspace = document.getElementById('tenant-workspace');
  var tenantDocsSection = document.getElementById('tenant-docs-section');
  var tenantDocsTable = document.getElementById('tenant-docs-table');
  var tenantDocsTbody = document.getElementById('tenant-docs-tbody');
  var tenantDocsEmpty = document.getElementById('tenant-docs-empty');
  var tenantDocsAlert = document.getElementById('tenant-docs-alert');
  var btnNewDoc = document.getElementById('btn-new-doc');

  var tenantDocFormSection = document.getElementById('tenant-doc-form-section');
  var docForm = document.getElementById('doc-form');
  var docFormTitle = document.getElementById('doc-form-title');
  var docFormDesc = document.getElementById('doc-form-desc');
  var docFormError = document.getElementById('doc-form-error');
  var docEditId = document.getElementById('doc-edit-id');
  var docTitleInput = document.getElementById('doc-title-input');
  var docContentInput = document.getElementById('doc-content-input');
  var btnSaveDoc = document.getElementById('btn-save-doc');
  var btnCancelDocForm = document.getElementById('btn-cancel-doc-form');

  var tenantDocViewSection = document.getElementById('tenant-doc-view-section');
  var viewDocTitle = document.getElementById('view-doc-title');
  var viewDocId = document.getElementById('view-doc-id');
  var viewDocKeyVer = document.getElementById('view-doc-key-ver');
  var viewDocCreated = document.getElementById('view-doc-created');
  var viewDocContent = document.getElementById('view-doc-content');
  var btnEditCurrentDoc = document.getElementById('btn-edit-current-doc');
  var btnBackToDocs = document.getElementById('btn-back-to-docs');

  // Admin Dashboard Views
  var adminDashboard = document.getElementById('admin-dashboard');

  // Modal
  var confirmModal = document.getElementById('confirm-modal');
  var btnConfirmCancel = document.getElementById('btn-confirm-cancel');
  var btnConfirmAction = document.getElementById('btn-confirm-action');

  // --- Network Helper ---
  async function apiFetch(url, options) {
    options = options || {};
    options.headers = options.headers || {};

    if (authToken) {
      options.headers['Authorization'] = 'Bearer ' + authToken;
    }

    var response;
    try {
      response = await fetch(url, options);
    } catch (err) {
      throw new Error('Network error. Check server connectivity.');
    }

    if (response.status === 401) {
      handleSignOut();
      showLoginError('Session expired or unauthorized. Please sign in again.');
      throw new Error('Unauthorized');
    }

    return response;
  }

  // --- Authentication Handlers ---
  function handleSignOut() {
    authToken = null;
    currentUser = null;
    pendingDeleteDocId = null;

    // Clear forms safely
    loginForm.reset();
    docForm.reset();

    // Reset views
    headerMeta.style.display = 'none';
    appShell.style.display = 'none';
    tenantWorkspace.style.display = 'none';
    adminDashboard.style.display = 'none';
    loginView.style.display = 'flex';
  }

  function showLoginError(msg) {
    loginError.textContent = msg;
    loginError.style.display = 'block';
  }

  function hideLoginError() {
    loginError.textContent = '';
    loginError.style.display = 'none';
  }

  loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    hideLoginError();

    var email = loginEmailInput.value.trim();
    var password = loginPassInput.value;

    if (!email || !password) {
      showLoginError('Please enter both email and password.');
      return;
    }

    btnLoginSubmit.disabled = true;
    btnLoginSubmit.textContent = 'Signing in...';

    try {
      var res = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password })
      });

      if (!res.ok) {
        var errJson = await res.json().catch(function () { return {}; });
        showLoginError(errJson.detail || 'Invalid email or password.');
        return;
      }

      var tokenData = await res.json();
      authToken = tokenData.access_token;

      // Fetch user profile context
      var userRes = await apiFetch('/admin/dashboard/me');
      if (!userRes.ok) {
        showLoginError('Failed to retrieve user context.');
        return;
      }

      currentUser = await userRes.json();
      renderAppShell();
    } catch (err) {
      showLoginError(err.message || 'An error occurred during sign in.');
    } finally {
      btnLoginSubmit.disabled = false;
      btnLoginSubmit.textContent = 'Sign in';
    }
  });

  btnSignout.addEventListener('click', handleSignOut);

  // --- Shell Rendering ---
  function renderAppShell() {
    loginView.style.display = 'none';
    appShell.style.display = 'flex';

    headerEmail.textContent = currentUser.email;
    headerTenant.textContent = currentUser.tenant_name || 'Tenant Workspace';
    headerMeta.style.display = 'flex';

    // Clear sidebar navigation
    while (sidebarNav.firstChild) {
      sidebarNav.removeChild(sidebarNav.firstChild);
    }

    if (currentUser.role === 'platform_admin') {
      tenantWorkspace.style.display = 'none';
      adminDashboard.style.display = 'block';
      renderAdminSidebar();
      loadAllAdminSections();
    } else {
      adminDashboard.style.display = 'none';
      tenantWorkspace.style.display = 'block';
      renderTenantSidebar();
      showDocsList();
      loadTenantDocuments();
    }
  }

  // --- Status Dot Helper ---
  function createStatusBadge(text, dotType) {
    var span = document.createElement('span');
    span.className = 'status-indicator';

    var dot = document.createElement('span');
    dot.className = 'dot ' + (dotType || 'dot-unknown');

    var label = document.createElement('span');
    label.textContent = text;

    span.appendChild(dot);
    span.appendChild(label);
    return span;
  }

  function getDotTypeForStatus(statusStr) {
    var s = String(statusStr || '').toUpperCase();
    if (s === 'BLOCKED' || s === 'INTACT' || s === 'ACTIVE' || s === 'PASSED' || s === 'NO_LEAK_DETECTED' || s === 'CAUGHT') {
      return 'dot-blocked';
    }
    if (s === 'LEAKED' || s === 'COMPROMISED' || s === 'DESTROYED' || s === 'LEAK_DETECTED' || s === 'MISSED') {
      return 'dot-leaked';
    }
    if (s === 'RETIRED' || s === 'INCONCLUSIVE' || s === 'MASKED') {
      return 'dot-retired';
    }
    return 'dot-unknown';
  }

  // =========================================================================
  // TENANT WORKSPACE CONTROLLER
  // =========================================================================
  function renderTenantSidebar() {
    var docsBtn = document.createElement('button');
    docsBtn.className = 'nav-link active';
    docsBtn.textContent = 'Documents';
    docsBtn.addEventListener('click', function () {
      setActiveNavLink(docsBtn);
      showDocsList();
      loadTenantDocuments();
    });

    var newDocBtn = document.createElement('button');
    newDocBtn.className = 'nav-link';
    newDocBtn.textContent = 'New document';
    newDocBtn.addEventListener('click', function () {
      setActiveNavLink(newDocBtn);
      showCreateDocForm();
    });

    sidebarNav.appendChild(docsBtn);
    sidebarNav.appendChild(newDocBtn);
  }

  function setActiveNavLink(activeEl) {
    var links = sidebarNav.querySelectorAll('.nav-link');
    for (var i = 0; i < links.length; i++) {
      links[i].classList.remove('active');
    }
    activeEl.classList.add('active');
  }

  function showDocsList() {
    tenantDocsSection.style.display = 'block';
    tenantDocFormSection.style.display = 'none';
    tenantDocViewSection.style.display = 'none';
  }

  function showCreateDocForm() {
    tenantDocsSection.style.display = 'none';
    tenantDocFormSection.style.display = 'block';
    tenantDocViewSection.style.display = 'none';

    docFormTitle.textContent = 'New document';
    docFormDesc.textContent = 'Provide document title and content. Tenant identity is attached server-side.';
    docEditId.value = '';
    docTitleInput.value = '';
    docContentInput.value = '';
    docFormError.style.display = 'none';
    btnSaveDoc.textContent = 'Create document';
  }

  function showEditDocForm(doc) {
    tenantDocsSection.style.display = 'none';
    tenantDocFormSection.style.display = 'block';
    tenantDocViewSection.style.display = 'none';

    docFormTitle.textContent = 'Edit document';
    docFormDesc.textContent = 'Update document title and content.';
    docEditId.value = doc.id;
    docTitleInput.value = doc.title;
    docContentInput.value = doc.content || '';
    docFormError.style.display = 'none';
    btnSaveDoc.textContent = 'Save changes';
  }

  function showViewDoc(doc) {
    tenantDocsSection.style.display = 'none';
    tenantDocFormSection.style.display = 'none';
    tenantDocViewSection.style.display = 'block';

    viewDocTitle.textContent = doc.title;
    viewDocId.textContent = doc.id;
    viewDocKeyVer.textContent = doc.key_version != null ? doc.key_version : '1';
    viewDocCreated.textContent = doc.created_at || '—';
    viewDocContent.textContent = doc.content || '';

    btnEditCurrentDoc.onclick = function () {
      showEditDocForm(doc);
    };
  }

  btnNewDoc.addEventListener('click', showCreateDocForm);
  btnCancelDocForm.addEventListener('click', showDocsList);
  btnBackToDocs.addEventListener('click', showDocsList);

  async function loadTenantDocuments() {
    tenantDocsAlert.style.display = 'none';

    // Clear table rows
    while (tenantDocsTbody.firstChild) {
      tenantDocsTbody.removeChild(tenantDocsTbody.firstChild);
    }

    try {
      var res = await apiFetch('/documents');
      if (!res.ok) {
        throw new Error('Failed to load documents.');
      }

      var docs = await res.json();
      if (!docs || docs.length === 0) {
        tenantDocsTable.style.display = 'none';
        tenantDocsEmpty.style.display = 'block';
        return;
      }

      tenantDocsTable.style.display = 'table';
      tenantDocsEmpty.style.display = 'none';

      for (var i = 0; i < docs.length; i++) {
        (function (doc) {
          var tr = document.createElement('tr');

          // Title (Safe textContent)
          var tdTitle = document.createElement('td');
          tdTitle.style.fontWeight = '500';
          tdTitle.textContent = doc.title;
          tr.appendChild(tdTitle);

          // ID (Safe textContent)
          var tdId = document.createElement('td');
          var codeId = document.createElement('code');
          codeId.textContent = doc.id;
          tdId.appendChild(codeId);
          tr.appendChild(tdId);

          // Key Version
          var tdKey = document.createElement('td');
          tdKey.className = 'num';
          tdKey.textContent = doc.key_version != null ? doc.key_version : '1';
          tr.appendChild(tdKey);

          // Created
          var tdCreated = document.createElement('td');
          tdCreated.style.fontSize = '13px';
          tdCreated.textContent = doc.created_at ? new Date(doc.created_at).toLocaleString() : '—';
          tr.appendChild(tdCreated);

          // Actions
          var tdActions = document.createElement('td');
          tdActions.style.whiteSpace = 'nowrap';

          var viewBtn = document.createElement('button');
          viewBtn.type = 'button';
          viewBtn.className = 'btn btn-sm';
          viewBtn.textContent = 'View';
          viewBtn.style.marginRight = '4px';
          viewBtn.addEventListener('click', async function () {
            viewBtn.disabled = true;
            try {
              var singleRes = await apiFetch('/documents/' + doc.id);
              if (singleRes.ok) {
                var singleDoc = await singleRes.json();
                showViewDoc(singleDoc);
              }
            } finally {
              viewBtn.disabled = false;
            }
          });

          var editBtn = document.createElement('button');
          editBtn.type = 'button';
          editBtn.className = 'btn btn-sm';
          editBtn.textContent = 'Edit';
          editBtn.style.marginRight = '4px';
          editBtn.addEventListener('click', async function () {
            editBtn.disabled = true;
            try {
              var singleRes = await apiFetch('/documents/' + doc.id);
              if (singleRes.ok) {
                var singleDoc = await singleRes.json();
                showEditDocForm(singleDoc);
              }
            } finally {
              editBtn.disabled = false;
            }
          });

          var delBtn = document.createElement('button');
          delBtn.type = 'button';
          delBtn.className = 'btn btn-sm btn-danger';
          delBtn.textContent = 'Delete';
          delBtn.addEventListener('click', function () {
            requestDocumentDelete(doc.id, doc.title);
          });

          tdActions.appendChild(viewBtn);
          tdActions.appendChild(editBtn);
          tdActions.appendChild(delBtn);
          tr.appendChild(tdActions);

          tenantDocsTbody.appendChild(tr);
        })(docs[i]);
      }
    } catch (err) {
      tenantDocsAlert.textContent = err.message || 'Error loading documents.';
      tenantDocsAlert.style.display = 'block';
    }
  }

  // Document Save (Create or Update)
  docForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    docFormError.style.display = 'none';

    var id = docEditId.value;
    var title = docTitleInput.value.trim();
    var content = docContentInput.value;

    if (!title) {
      docFormError.textContent = 'Document title is required.';
      docFormError.style.display = 'block';
      return;
    }

    btnSaveDoc.disabled = true;
    btnSaveDoc.textContent = 'Saving...';

    try {
      var isEdit = Boolean(id);
      var url = isEdit ? '/documents/' + id : '/documents';
      var method = isEdit ? 'PUT' : 'POST';

      // Crucial: The UI never sends a tenant_id!
      var payload = {
        title: title,
        content: content
      };

      var res = await apiFetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        var errData = await res.json().catch(function () { return {}; });
        throw new Error(errData.detail || 'Failed to save document.');
      }

      showDocsList();
      loadTenantDocuments();
    } catch (err) {
      docFormError.textContent = err.message || 'Error saving document.';
      docFormError.style.display = 'block';
    } finally {
      btnSaveDoc.disabled = false;
      btnSaveDoc.textContent = 'Save document';
    }
  });

  // Document Delete Confirmation
  function requestDocumentDelete(docId, docTitle) {
    pendingDeleteDocId = docId;
    var msgEl = document.getElementById('confirm-modal-msg');
    msgEl.textContent = 'Are you sure you want to delete "' + docTitle + '"? This action is permanent.';
    confirmModal.style.display = 'flex';
  }

  btnConfirmCancel.addEventListener('click', function () {
    pendingDeleteDocId = null;
    confirmModal.style.display = 'none';
  });

  btnConfirmAction.addEventListener('click', async function () {
    if (!pendingDeleteDocId) return;

    btnConfirmAction.disabled = true;
    btnConfirmAction.textContent = 'Deleting...';

    try {
      var res = await apiFetch('/documents/' + pendingDeleteDocId, {
        method: 'DELETE'
      });

      if (!res.ok) {
        throw new Error('Failed to delete document.');
      }

      confirmModal.style.display = 'none';
      pendingDeleteDocId = null;
      loadTenantDocuments();
    } catch (err) {
      alert(err.message || 'Error deleting document.');
    } finally {
      btnConfirmAction.disabled = false;
      btnConfirmAction.textContent = 'Confirm delete';
    }
  });

  // =========================================================================
  // ADMIN DASHBOARD CONTROLLER
  // =========================================================================
  function renderAdminSidebar() {
    var sections = [
      { id: 'section-verification', label: 'Latest verification' },
      { id: 'section-layer-kill', label: 'Layer-kill matrix' },
      { id: 'section-mutation', label: 'Mutation testing' },
      { id: 'section-noisy-neighbour', label: 'Noisy neighbour' },
      { id: 'section-metrics', label: 'Tenant metrics' },
      { id: 'section-keys', label: 'Tenant keys' }
    ];

    for (var i = 0; i < sections.length; i++) {
      (function (sec, idx) {
        var btn = document.createElement('button');
        btn.className = 'nav-link' + (idx === 0 ? ' active' : '');
        btn.textContent = sec.label;
        btn.addEventListener('click', function () {
          setActiveNavLink(btn);
          var targetEl = document.getElementById(sec.id);
          if (targetEl) {
            targetEl.scrollIntoView({ behavior: 'smooth' });
          }
        });
        sidebarNav.appendChild(btn);
      })(sections[i], i);
    }
  }

  function loadAllAdminSections() {
    loadVerificationSection();
    loadLayerKillSection();
    loadMutationSection();
    loadNoisyNeighbourSection();
    loadMetricsSection();
    loadKeysSection();
  }

  // 1. Verification Section
  async function loadVerificationSection() {
    var contentEl = document.getElementById('verif-content');
    var emptyEl = document.getElementById('verif-empty');
    var timeEl = document.getElementById('verif-run-time');
    var tbody = document.getElementById('verif-table-body');

    try {
      var res = await apiFetch('/admin/dashboard/verification');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';
      timeEl.textContent = data.summary.generated_at_utc ? new Date(data.summary.generated_at_utc).toLocaleString() : '';

      // Exact stored verdict and counts
      var verdictEl = document.getElementById('verif-verdict');
      while (verdictEl.firstChild) verdictEl.removeChild(verdictEl.firstChild);
      verdictEl.appendChild(createStatusBadge(data.summary.overall_verdict, getDotTypeForStatus(data.summary.overall_verdict)));

      document.getElementById('verif-total').textContent = data.summary.total_attacks_run;
      document.getElementById('verif-blocked').textContent = data.summary.blocked_attacks;
      document.getElementById('verif-leaked').textContent = data.summary.leaked_attacks;
      document.getElementById('verif-inconclusive').textContent = data.summary.inconclusive_attacks;
      document.getElementById('verif-canary').textContent = data.summary.tenant_b_canary_integrity;
      document.getElementById('verif-list-leak').textContent = data.summary.list_leak_check;

      // Attacks Table
      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var attacks = data.attacks || [];
      for (var i = 0; i < attacks.length; i++) {
        var a = attacks[i];
        var tr = document.createElement('tr');

        var tdMethod = document.createElement('td');
        tdMethod.style.fontWeight = '600';
        tdMethod.textContent = a.method;
        tr.appendChild(tdMethod);

        var tdPath = document.createElement('td');
        var codePath = document.createElement('code');
        codePath.textContent = a.target_path;
        tdPath.appendChild(codePath);
        tr.appendChild(tdPath);

        var tdStatus = document.createElement('td');
        tdStatus.className = 'num';
        tdStatus.textContent = a.status_code;
        tr.appendChild(tdStatus);

        var tdOutcome = document.createElement('td');
        tdOutcome.appendChild(createStatusBadge(a.outcome, getDotTypeForStatus(a.outcome)));
        tr.appendChild(tdOutcome);

        var tdControl = document.createElement('td');
        tdControl.textContent = a.blocking_control;
        tr.appendChild(tdControl);

        tbody.appendChild(tr);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 2. Layer-Kill Section
  async function loadLayerKillSection() {
    var contentEl = document.getElementById('layer-content');
    var emptyEl = document.getElementById('layer-empty');
    var timeEl = document.getElementById('layer-run-time');
    var tbody = document.getElementById('layer-table-body');

    try {
      var res = await apiFetch('/admin/dashboard/layer-kill');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';
      timeEl.textContent = data.generated_at_utc ? new Date(data.generated_at_utc).toLocaleString() : '';

      var verdictEl = document.getElementById('layer-verdict');
      while (verdictEl.firstChild) verdictEl.removeChild(verdictEl.firstChild);
      verdictEl.appendChild(createStatusBadge(data.overall_verdict, getDotTypeForStatus(data.overall_verdict)));

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var configs = data.configurations || [];
      for (var i = 0; i < configs.length; i++) {
        var c = configs[i];
        var tr = document.createElement('tr');

        var tdConfig = document.createElement('td');
        tdConfig.style.fontWeight = '500';
        tdConfig.textContent = c.configuration;
        tr.appendChild(tdConfig);

        var tdA = document.createElement('td');
        tdA.textContent = c.layer_a_app_check;
        tr.appendChild(tdA);

        var tdB = document.createElement('td');
        tdB.textContent = c.layer_b_db_rls;
        tr.appendChild(tdB);

        var tdC = document.createElement('td');
        tdC.textContent = c.layer_c_query_filter;
        tr.appendChild(tdC);

        var tdR = document.createElement('td');
        tdR.className = 'num';
        tdR.textContent = c.leaks.read;
        tr.appendChild(tdR);

        var tdW = document.createElement('td');
        tdW.className = 'num';
        tdW.textContent = c.leaks.write;
        tr.appendChild(tdW);

        var tdU = document.createElement('td');
        tdU.className = 'num';
        tdU.textContent = c.leaks.update;
        tr.appendChild(tdU);

        var tdD = document.createElement('td');
        tdD.className = 'num';
        tdD.textContent = c.leaks.delete;
        tr.appendChild(tdD);

        var tdProt = document.createElement('td');
        tdProt.style.fontSize = '12px';
        tdProt.style.color = 'var(--text-muted)';
        tdProt.textContent = (c.active_protections || []).join(', ');
        tr.appendChild(tdProt);

        var tdVerd = document.createElement('td');
        tdVerd.appendChild(createStatusBadge(c.config_verdict, getDotTypeForStatus(c.config_verdict)));
        tr.appendChild(tdVerd);

        tbody.appendChild(tr);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 3. Mutation Section
  async function loadMutationSection() {
    var contentEl = document.getElementById('mut-content');
    var emptyEl = document.getElementById('mut-empty');
    var timeEl = document.getElementById('mut-run-time');
    var scoreEl = document.getElementById('mut-score');
    var tbody = document.getElementById('mut-table-body');

    try {
      var res = await apiFetch('/admin/dashboard/mutation');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';
      timeEl.textContent = data.timestamp ? new Date(data.timestamp).toLocaleString() : '';
      scoreEl.textContent = data.isolation_mutation_score;

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var mutations = data.mutations || [];
      for (var i = 0; i < mutations.length; i++) {
        var m = mutations[i];
        var tr = document.createElement('tr');

        var tdName = document.createElement('td');
        tdName.style.fontWeight = '500';
        tdName.textContent = m.name;
        tr.appendChild(tdName);

        var tdLayer = document.createElement('td');
        tdLayer.textContent = m.mutated_layer;
        tr.appendChild(tdLayer);

        var tdMethod = document.createElement('td');
        var codeM = document.createElement('code');
        codeM.textContent = m.detection_method;
        tdMethod.appendChild(codeM);
        tr.appendChild(tdMethod);

        var tdIso = document.createElement('td');
        tdIso.appendChild(createStatusBadge(m.isolated_result, getDotTypeForStatus(m.isolated_result)));
        tr.appendChild(tdIso);

        var tdMask = document.createElement('td');
        tdMask.appendChild(createStatusBadge(m.masked_result, getDotTypeForStatus(m.masked_result)));
        tr.appendChild(tdMask);

        var tdBase = document.createElement('td');
        tdBase.textContent = m.baseline_restored ? 'Yes' : 'No';
        tr.appendChild(tdBase);

        tbody.appendChild(tr);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 4. Noisy-Neighbour Section
  async function loadNoisyNeighbourSection() {
    var contentEl = document.getElementById('noisy-content');
    var emptyEl = document.getElementById('noisy-empty');
    var timeEl = document.getElementById('noisy-run-time');
    var tbody = document.getElementById('noisy-table-body');
    var amendmentsList = document.getElementById('noisy-amendments-list');

    try {
      var res = await apiFetch('/admin/dashboard/noisy-neighbour');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';
      timeEl.textContent = data.generated_at_utc ? new Date(data.generated_at_utc).toLocaleString() : '';

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var summaries = data.summaries || [];
      for (var i = 0; i < summaries.length; i++) {
        var s = summaries[i];
        var tr = document.createElement('tr');

        var tdStrat = document.createElement('td');
        tdStrat.style.fontWeight = '500';
        tdStrat.textContent = s.strategy_label;
        tr.appendChild(tdStrat);

        var tdLoad = document.createElement('td');
        tdLoad.textContent = s.load_type;
        tr.appendChild(tdLoad);

        var tdP50 = document.createElement('td');
        tdP50.className = 'num';
        tdP50.textContent = s.beta_p50_ms.mean + ' (±' + s.beta_p50_ms.std + ')';
        tr.appendChild(tdP50);

        var tdP95 = document.createElement('td');
        tdP95.className = 'num';
        tdP95.textContent = s.beta_p95_ms.mean + ' (±' + s.beta_p95_ms.std + ')';
        tr.appendChild(tdP95);

        var tdErr = document.createElement('td');
        tdErr.className = 'num';
        tdErr.textContent = s.beta_error_rate.mean + ' (±' + s.beta_error_rate.std + ')';
        tr.appendChild(tdErr);

        var td429 = document.createElement('td');
        td429.className = 'num';
        td429.textContent = s.acme_429.mean + ' (±' + s.acme_429.std + ')';
        tr.appendChild(td429);

        var tdTimeouts = document.createElement('td');
        tdTimeouts.className = 'num';
        tdTimeouts.textContent = s.acme_timeouts.mean + ' (±' + s.acme_timeouts.std + ')';
        tr.appendChild(tdTimeouts);

        tbody.appendChild(tr);
      }

      // Amendments list
      while (amendmentsList.firstChild) amendmentsList.removeChild(amendmentsList.firstChild);
      var amendments = data.amendments || [];
      for (var a = 0; a < amendments.length; a++) {
        var li = document.createElement('li');
        li.textContent = amendments[a];
        amendmentsList.appendChild(li);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 5. Per-Tenant Metrics Section
  async function loadMetricsSection() {
    var contentEl = document.getElementById('metrics-content');
    var emptyEl = document.getElementById('metrics-empty');
    var tbody = document.getElementById('metrics-table-body');
    var chartContainer = document.getElementById('metrics-chart-container');

    try {
      var res = await apiFetch('/admin/metrics?window_minutes=60');
      var data = await res.json();

      var tenants = (data && data.tenants) || [];
      if (tenants.length === 0) {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var chartData = [];

      for (var i = 0; i < tenants.length; i++) {
        var t = tenants[i];
        var tr = document.createElement('tr');

        var tdId = document.createElement('td');
        var codeId = document.createElement('code');
        codeId.textContent = t.tenant_id;
        tdId.appendChild(codeId);
        tr.appendChild(tdId);

        var tdReq = document.createElement('td');
        tdReq.className = 'num';
        tdReq.textContent = t.request_count.toLocaleString();
        tr.appendChild(tdReq);

        var tdErr = document.createElement('td');
        tdErr.className = 'num';
        tdErr.textContent = t.error_count.toLocaleString();
        tr.appendChild(tdErr);

        var tdLat = document.createElement('td');
        tdLat.className = 'num';
        tdLat.textContent = t.avg_latency_ms.toFixed(2);
        tr.appendChild(tdLat);

        tbody.appendChild(tr);

        chartData.push({
          label: t.tenant_id.substring(0, 8),
          value: t.avg_latency_ms
        });
      }

      // Render Bar Chart using local vendor tool
      if (window.TenantChart && window.TenantChart.renderBarChart) {
        window.TenantChart.renderBarChart(chartContainer, {
          data: chartData,
          labelKey: 'label',
          valueKey: 'value',
          unit: 'ms',
          height: 180
        });
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 6. Tenant Key Status Section
  async function loadKeysSection() {
    var contentEl = document.getElementById('keys-content');
    var emptyEl = document.getElementById('keys-empty');
    var tbody = document.getElementById('keys-table-body');

    try {
      var res = await apiFetch('/admin/dashboard/keys');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var tenants = data.tenants || [];
      for (var i = 0; i < tenants.length; i++) {
        var t = tenants[i];
        var keys = t.keys || [];

        if (keys.length === 0) {
          var trEmpty = document.createElement('tr');
          var tdTName = document.createElement('td');
          tdTName.style.fontWeight = '500';
          tdTName.textContent = t.tenant_name;
          trEmpty.appendChild(tdTName);

          var tdTId = document.createElement('td');
          var codeTId = document.createElement('code');
          codeTId.textContent = t.tenant_id;
          tdTId.appendChild(codeTId);
          trEmpty.appendChild(tdTId);

          var tdNoKey = document.createElement('td');
          tdNoKey.colSpan = 5;
          tdNoKey.style.color = 'var(--text-muted)';
          tdNoKey.textContent = 'No keys provisioned';
          trEmpty.appendChild(tdNoKey);

          tbody.appendChild(trEmpty);
          continue;
        }

        for (var k = 0; k < keys.length; k++) {
          var keyItem = keys[k];
          var tr = document.createElement('tr');

          var tdName = document.createElement('td');
          tdName.style.fontWeight = '500';
          tdName.textContent = t.tenant_name;
          tr.appendChild(tdName);

          var tdId = document.createElement('td');
          var codeId = document.createElement('code');
          codeId.textContent = t.tenant_id;
          tdId.appendChild(codeId);
          tr.appendChild(tdId);

          var tdVer = document.createElement('td');
          tdVer.className = 'num';
          tdVer.textContent = keyItem.key_version;
          tr.appendChild(tdVer);

          var tdStat = document.createElement('td');
          tdStat.appendChild(createStatusBadge(keyItem.status, getDotTypeForStatus(keyItem.status)));
          tr.appendChild(tdStat);

          var tdCreated = document.createElement('td');
          tdCreated.style.fontSize = '12px';
          tdCreated.textContent = keyItem.created_at ? new Date(keyItem.created_at).toLocaleString() : '—';
          tr.appendChild(tdCreated);

          var tdRet = document.createElement('td');
          tdRet.style.fontSize = '12px';
          tdRet.textContent = keyItem.retired_at ? new Date(keyItem.retired_at).toLocaleString() : '—';
          tr.appendChild(tdRet);

          var tdDes = document.createElement('td');
          tdDes.style.fontSize = '12px';
          tdDes.textContent = keyItem.destroyed_at ? new Date(keyItem.destroyed_at).toLocaleString() : '—';
          tr.appendChild(tdDes);

          tbody.appendChild(tr);
        }
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

})();
